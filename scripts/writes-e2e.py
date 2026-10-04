#!/usr/bin/env python3
"""Browser E2E for the UI write paths (playwright + real chromium).

Boots the embedded server, then drives the real SPA to exercise the
newly-wired write surfaces (all side-effect-safe):
  1. Jobs: create a job through the + New job form (task created via API).
  2. Updates: package DRY-RUN apply (no packages are installed).
  3. Provision: start a run against an unreachable host (fails fast at
     connect) and cancel it.
Usage: python3 scripts/writes-e2e.py
"""
import os, subprocess, sys, time, signal, tempfile, shutil, json, urllib.request

PORT = int(os.environ.get("PARTOUT_WRITES_E2E_PORT", "18473"))
GO = "go" if shutil.which("go") else "/usr/local/go/bin/go"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = tempfile.mkdtemp(prefix="partout-writes-")
BIN = os.path.join(WORK, "partout")

FAILURES = []
def check(name, cond, extra=""):
    print(("  PASS " if cond else "  FAIL ") + name + ("" if cond else "  <<< " + str(extra)[:200]))
    if not cond: FAILURES.append(name)

def _keyscan_ok():
    """True when a loopback ssh-keyscan returns a host key (gate is testable)."""
    try:
        out = subprocess.run(["ssh-keyscan", "-t", "ed25519", "localhost"],
                             capture_output=True, timeout=15)
        return out.returncode == 0 and b"ssh-" in out.stdout
    except Exception:
        return False

def curl(method, path, body=None, token=None):
    url = f"http://127.0.0.1:{PORT}/api/v1{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} on {req.method} {url}") from e

srv = None
try:
    subprocess.run([GO, "build", "-o", BIN, "./cmd/partout"], cwd=REPO, check=True)
    run = os.path.join(WORK, "run"); os.makedirs(run)
    logf = open(os.path.join(WORK, "server.log"), "wb")
    LOGPATH = os.path.join(WORK, "server.log")
    srv = subprocess.Popen([BIN], cwd=run, env={**os.environ,
        "PARTOUT_ADMIN_PASSWORD": "w-e2e-pass", "PARTOUT_TOKEN_ADMIN": "w-e2e-token",
        "PARTOUT_PORT": str(PORT),
        "PARTOUT_DB_PATH": os.path.join(run, "p.db"), "PARTOUT_DATA_DIR": os.path.join(run, "agent"),
        # Isolate the SSH trust store: the provisioner's known_hosts check would
        # otherwise consult the real ~/.ssh, where loopback entries may already
        # exist, silently skipping the key_confirm gate this suite verifies.
        "PARTOUT_SSH_DIR": os.path.join(run, "ssh"),
        "PARTOUT_MODE": "embedded"}, stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=1); break
        except Exception: time.sleep(0.5)
    else:
        raise SystemExit("server did not start")
    hosts = {"items": []}
    for _ in range(60):
        try:
            h = curl("GET", "/hosts", token="w-e2e-token")
            if h.get("items"): hosts = h; break
        except Exception: pass
        time.sleep(0.5)
    host = hosts["items"][0]["id"]

    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.on("dialog", lambda d: d.accept())
        page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        page.fill('input[autocomplete="username"]', "admin")
        page.fill('input[autocomplete="current-password"]', "w-e2e-pass")
        page.click("button[type=submit]")
        page.wait_for_selector(".shell", timeout=15000)

        # ---- 1. Jobs: create via the UI form ----
        task = curl("POST", "/tasks", {"name": "w-e2e task", "steps": [{"cmd": "true"}]}, token="w-e2e-token")
        page.goto(f"http://127.0.0.1:{PORT}/#/jobs")
        page.wait_for_timeout(1200)
        page.click("button:has-text('New job')")
        page.wait_for_timeout(300)
        form = page.locator("div[style*='brand-subtle']")
        form.locator("input").first.fill("w-e2e cron job")
        page.wait_for_function("(tid) => { const s = document.querySelector('div[style*=brand-subtle] select'); return s && [...s.options].some(o => o.value === tid); }", arg=task["id"], timeout=10000)
        form.locator("select").first.select_option(task["id"])
        # cron input is the 2nd text input in the form (name is 1st)
        form.locator("input").nth(1).fill("0 4 * * *")
        form.locator("input").nth(2).fill("all")
        page.wait_for_timeout(200)
        form.locator("button:has-text('Create')").click()
        page.wait_for_timeout(1500)
        jobs_now = curl("GET", "/jobs", token="w-e2e-token") or []
        created = [j for j in (jobs_now if isinstance(jobs_now, list) else jobs_now.get("items", [])) if j.get("name") == "w-e2e cron job"]
        check("jobs: created via UI (API confirms)", bool(created),
              "no job named 'w-e2e cron job' in GET /jobs")
        check("jobs: created job row renders",
              "w-e2e cron job" in (page.evaluate("() => document.body.innerText") or ""),
              "new job row missing")

        # ---- 2. Updates: package dry-run apply (safe) ----
        page.goto(f"http://127.0.0.1:{PORT}/#/updates")
        page.wait_for_timeout(1800)
        before = {a.get("id") for a in (curl("GET", "/packages/actions", token="w-e2e-token") or [])}
        page.locator("label:has-text('dry run') input").check()
        page.click("button:has-text('Apply')")
        # The UI click creates the action asynchronously; wait for a NEW action to
        # reach a terminal state (a dry-run of apt takes a second or two).
        new_action = None
        for _ in range(90):
            acts = curl("GET", "/packages/actions", token="w-e2e-token") or []
            cand = [a for a in acts if a.get("id") not in before]
            if cand and cand[0].get("status") in ("succeeded", "failed"):
                new_action = cand[0]
                break
            if cand:
                new_action = cand[0]  # created but still running
            time.sleep(1)
        check("packages: dry-run action created via UI",
              bool(new_action) and new_action.get("kind") == "dry_run",
              new_action and new_action.get("kind"))
        check("packages: dry-run action succeeded",
              bool(new_action) and new_action.get("status") == "succeeded",
              new_action and (new_action.get("status"), new_action.get("error")))
        check("packages: dry-run produced a summary",
              bool(new_action) and bool(new_action.get("dry_summary")),
              "dry_summary empty")
        check("packages: action row rendered in UI",
              bool(new_action) and new_action["id"] in (page.evaluate("() => document.body.innerText") or ""),
              "action id not visible on the Updates page")

        # ---- 3. Provision: start a run (fails fast) then cancel ----
        page.goto(f"http://127.0.0.1:{PORT}/#/provision")
        page.wait_for_timeout(1000)
        prov_before = {r.get("id") for r in ((curl("GET", "/provision-runs", token="w-e2e-token") or {}).get("items") or [])}
        page.fill("input[placeholder='user@host']", "nobody@127.0.0.1")
        page.click("button:has-text('Start provisioning')")
        page.wait_for_timeout(1200)
        prov_after = (curl("GET", "/provision-runs", token="w-e2e-token") or {}).get("items") or []
        new_runs = [r for r in prov_after if r.get("id") not in prov_before and r.get("host") == "nobody@127.0.0.1"]
        check("provision: run created via UI", bool(new_runs), "no new provision run for nobody@127.0.0.1")
        check("provision: new run row appears in UI",
              "nobody@127.0.0.1" in (page.evaluate("() => document.body.innerText") or ""),
              "run row missing")
        # The run fails fast (unreachable host), so drive cancel explicitly
        # against the run we just created and assert the state transition.
        if new_runs:
            rid = new_runs[0]["id"]
            try:
                curl("POST", f"/provision-runs/{rid}/cancel", {}, token="w-e2e-token")
                state = next((r.get("state") for r in (curl("GET", "/provision-runs", token="w-e2e-token") or {}).get("items") or [] if r.get("id") == rid), None)
                check("provision: cancel drives terminal state", state in ("cancelled", "failed"), state)
            except RuntimeError as e:
                # Already terminal -> the API refuses to cancel; that is correct.
                state = next((r.get("state") for r in (curl("GET", "/provision-runs", token="w-e2e-token") or {}).get("items") or [] if r.get("id") == rid), None)
                check("provision: run already terminal (cancel refused)", state in ("cancelled", "failed"), str(e))
        else:
            check("provision: cancel drives terminal state", False, "no run to cancel")

        # ---- 4. Provision key-confirm gate (LIVE, via SSE) ----
        # This is the flagship "no silent TOFU" security gate. It regressed once:
        # the server emits "provision.key_confirm" but the UI listened for
        # "provision.key.confirmed", so the Confirm/Deny buttons never appeared
        # until a manual refresh. Driving a REAL ssh target (loopback) is the
        # only way to cover it: an unreachable host fails before keyscan.
        if shutil.which("ssh-keyscan") and _keyscan_ok():
            page.goto(f"http://127.0.0.1:{PORT}/#/provision")
            page.wait_for_timeout(800)
            before2 = {r.get("id") for r in ((curl("GET", "/provision-runs", token="w-e2e-token") or {}).get("items") or [])}
            page.fill("input[placeholder='user@host']", "root@localhost")
            page.click("button:has-text('Start provisioning')")
            # Wait for the run to pause at key_confirm (poll the API as ground truth).
            run = None
            for _ in range(30):
                items = (curl("GET", "/provision-runs", token="w-e2e-token") or {}).get("items") or []
                cand = [r for r in items if r.get("id") not in before2 and r.get("host") == "root@localhost"]
                if cand and cand[0].get("state") == "key_confirm":
                    run = cand[0]; break
                if cand and cand[0].get("state") in ("failed", "cancelled"):
                    run = cand[0]; break
                time.sleep(1)
            if run and run.get("state") == "key_confirm":
                check("provision: run paused at key_confirm", True)
                check("provision: fingerprint exposed", bool(run.get("fingerprint")), run.get("fingerprint"))
                # The UI must surface the gate WITHOUT a manual refresh (SSE).
                live = False
                for _ in range(15):
                    body = page.evaluate("() => document.body.innerText") or ""
                    if "Confirm key" in body:
                        live = True; break
                    time.sleep(1)
                check("provision: Confirm button appears live (SSE)", live,
                      "key-confirm gate did not appear without a manual refresh")
                if live:
                    page.click("button:has-text('Confirm key')")
                    page.wait_for_timeout(2500)
                    after = next((r.get("state") for r in (curl("GET", "/provision-runs", token="w-e2e-token") or {}).get("items") or [] if r.get("id") == run["id"]), None)
                    # Confirming resumes the run past the gate: it either advances
                    # (connecting/connected) or fails later at preflight, but it
                    # must no longer sit at key_confirm.
                    check("provision: confirm resumes past the gate",
                          after not in ("key_confirm", None), after)
            else:
                check("provision: run paused at key_confirm", False,
                      "state=%s err=%s (needs sshd on :22 and a fresh PARTOUT_SSH_DIR)" % (
                          run and run.get("state"), run and run.get("error")))
        else:
            print("  SKIP provision key-confirm gate (ssh-keyscan or a local sshd unavailable)")

        browser.close()

    if FAILURES:
        try:
            tail = open(LOGPATH, "rb").read()[-4000:].decode("utf-8", "replace")
            print("\n--- server.log tail (on failure) ---\n" + tail)
        except Exception as e:
            print("could not read server log:", e)

    sys.exit(1 if FAILURES else 0)
finally:
    if srv:
        try: srv.send_signal(signal.SIGTERM)
        except Exception: pass
    shutil.rmtree(WORK, ignore_errors=True)
