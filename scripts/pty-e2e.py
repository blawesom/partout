#!/usr/bin/env python3
"""Live PTY browser E2E (playwright + real chromium).

Boots the embedded server (server + local agent), logs into the real SPA,
opens a live terminal (xterm.js) on the local host, types a command, and
asserts the output round-trips through REST input + SSE output. Then closes
the session and asserts the replay renders.

Usage: scripts/pty-e2e.sh
"""
import os, subprocess, sys, time, signal, tempfile, shutil, json, urllib.request

PORT = int(os.environ.get("PARTOUT_PTY_E2E_PORT", "18472"))
GO = "go" if shutil.which("go") else "/usr/local/go/bin/go"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = tempfile.mkdtemp(prefix="partout-pty-")
BIN = os.path.join(WORK, "partout")

def curl(method, path, body=None, token=None):
    url = f"http://127.0.0.1:{PORT}/api/v1{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"null")

try:
    subprocess.run([GO, "build", "-o", BIN, "./cmd/partout"], cwd=REPO, check=True)
    run = os.path.join(WORK, "run"); os.makedirs(run)
    logf = open(os.path.join(WORK, "server.log"), "wb")
    srv = subprocess.Popen([BIN], cwd=run, env={**os.environ,
        "PARTOUT_ADMIN_PASSWORD": "pty-e2e-pass", "PARTOUT_TOKEN_ADMIN": "pty-e2e-token",
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
            h = curl("GET", "/hosts", token="pty-e2e-token")
            if h.get("items"):
                hosts = h; break
        except Exception: pass
        time.sleep(0.5)
    host = hosts["items"][0]["id"]
    login = curl("POST", "/auth/login", {"username": "admin", "password": "pty-e2e-pass"})
    token = login["token"]

    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.on("dialog", lambda d: d.accept())  # accept confirm() prompts (close session)
        page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        page.fill('input[autocomplete="username"]', "admin")
        page.fill('input[autocomplete="current-password"]', "pty-e2e-pass")
        page.click("button[type=submit]")
        page.wait_for_selector(".shell", timeout=15000)

        # Open a live terminal from the Sessions page.
        page.goto(f"http://127.0.0.1:{PORT}/#/sessions")
        page.wait_for_timeout(1500)
        page.select_option("select", index=1)  # first host (index 0 is the placeholder)
        page.fill('input[placeholder="bash"]', "bash")
        page.click("button:has-text('Open terminal')")
        page.wait_for_selector(".term-host .xterm", timeout=20000)
        print("  PASS terminal mounted (xterm in DOM)")

        # Give the shell a moment to print its prompt, then type a fixed command.
        page.wait_for_timeout(1500)
        page.evaluate("() => { const t = window.__partoutTerm; if (t) t.focus(); }")
        page.click(".term-host")
        page.wait_for_timeout(200)
        page.keyboard.type("echo pty-live-OK", delay=60)
        page.keyboard.press("Enter")

        # Wait for the output in the terminal buffer (renderer-independent).
        ok = False
        read_buf = "() => { const t = window.__partoutTerm; if (!t) return ''; const b = t.buffer.active; const out = []; for (let i = 0; i < b.length; i++) { const l = b.getLine(i); if (l) out.push(l.translateToString(true)); } return out.join('\\n'); }"
        text = ""
        for _ in range(40):
            text = page.evaluate(read_buf)
            if "pty-live-OK" in (text or ""):
                ok = True; break
            time.sleep(0.5)
        print(("  PASS " if ok else "  FAIL ") + "typed command output round-tripped through SSE")
        if not ok:
            print("  buffer:", (text or "")[-800:])

        # Close the session; the page should fall back to the recorded replay.
        page.click("button:has-text('Close session')")
        try:
            page.wait_for_function("() => { const b = document.body.innerText; return b.includes('(replay)') || b.includes('No replay data'); }", timeout=20000)
            print("  PASS session closed, replay view rendered")
        except Exception as e:
            print("  FAIL session closed replay: " + str(e)[:200])
            ok = False
        browser.close()

    sys.exit(0 if ok else 1)
finally:
    try: srv.send_signal(signal.SIGTERM)
    except Exception: pass
    shutil.rmtree(WORK, ignore_errors=True)
