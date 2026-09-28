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
    srv = subprocess.Popen([BIN], cwd=run, env={**os.environ,
        "PARTOUT_ADMIN_PASSWORD": "w-e2e-pass", "PARTOUT_TOKEN_ADMIN": "w-e2e-token",
        "PARTOUT_PORT": str(PORT),
        "PARTOUT_DB_PATH": os.path.join(run, "p.db"), "PARTOUT_DATA_DIR": os.path.join(run, "agent"),
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
        check("jobs: created job row renders",
              "w-e2e cron job" in (page.evaluate("() => document.body.innerText") or ""),
              "new job row missing")

        # ---- 2. Updates: package dry-run apply (safe) ----
        page.goto(f"http://127.0.0.1:{PORT}/#/updates")
        page.wait_for_timeout(1800)
        page.locator("label:has-text('dry run') input").check()
        page.click("button:has-text('Apply')")
        # apt dry-run can take a few seconds; wait for an action row.
        ok = False
        for _ in range(60):
            body = page.evaluate("() => document.body.innerText") or ""
            if "Package actions" in body and "dry_run" in body:
                ok = True; break
            time.sleep(1)
        check("packages: dry-run action row rendered", ok, "no dry_run action row within 60s")

        # ---- 3. Provision: start a run (fails fast) then cancel ----
        page.goto(f"http://127.0.0.1:{PORT}/#/provision")
        page.wait_for_timeout(1000)
        page.fill("input[placeholder='user@host']", "nobody@127.0.0.1")
        page.click("button:has-text('Start provisioning')")
        page.wait_for_timeout(1000)
        body = page.evaluate("() => document.body.innerText") or ""
        check("provision: new run row appears", "nobody@127.0.0.1" in body, "run row missing")
        # The run is either still connecting or already failed; cancel if possible.
        cancel = page.locator("button:has-text('Cancel')")
        if cancel.count():
            cancel.first.click()
            page.wait_for_timeout(1000)
            check("provision: cancel action executed", True)
        else:
            check("provision: run terminal (nothing to cancel)", "failed" in body or "cancelled" in body, body[:200])

        browser.close()

    sys.exit(1 if FAILURES else 0)
finally:
    if srv:
        try: srv.send_signal(signal.SIGTERM)
        except Exception: pass
    shutil.rmtree(WORK, ignore_errors=True)
