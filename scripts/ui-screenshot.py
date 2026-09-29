#!/usr/bin/env python3
"""Capture Web UI screenshots for the README (playwright + real chromium).

Boots the embedded server (server + local agent), waits for the fleet to be
populated, logs in, and screenshots the main pages into docs/screenshots/.
Usage: python3 scripts/ui-screenshot.py
"""
import os, subprocess, sys, time, signal, tempfile, shutil, json, urllib.request

PORT = int(os.environ.get("PARTOUT_SHOT_PORT", "18478"))
GO = "go" if shutil.which("go") else "/usr/local/go/bin/go"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "docs", "screenshots")
WORK = tempfile.mkdtemp(prefix="partout-shot-")
BIN = os.path.join(WORK, "partout")

def curl(method, path, body=None, token=None):
    url = f"http://127.0.0.1:{PORT}/api/v1{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"null")

os.makedirs(OUT, exist_ok=True)
srv = None
try:
    subprocess.run([GO, "build", "-o", BIN, "./cmd/partout"], cwd=REPO, check=True)
    run = os.path.join(WORK, "run"); os.makedirs(run)
    logf = open(os.path.join(WORK, "server.log"), "wb")
    srv = subprocess.Popen([BIN], cwd=run, env={**os.environ,
        "PARTOUT_ADMIN_PASSWORD": "shot-pass", "PARTOUT_TOKEN_ADMIN": "shot-token",
        "PARTOUT_PORT": str(PORT),
        "PARTOUT_DB_PATH": os.path.join(run, "p.db"), "PARTOUT_DATA_DIR": os.path.join(run, "agent"),
        "PARTOUT_MODE": "embedded"}, stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=1); break
        except Exception: time.sleep(0.5)
    else:
        raise SystemExit("server did not start")
    # Wait for the local agent to connect and upload facts (services page needs them).
    host = None
    for _ in range(90):
        try:
            items = curl("GET", "/hosts", token="shot-token").get("items") or []
            if items:
                host = items[0]
                # give the facts a moment so Observe pages render real data
                if host.get("state") == "connected":
                    break
        except Exception:
            pass
        time.sleep(0.5)
    if not host:
        raise SystemExit("no host connected")
    time.sleep(3)  # let the first facts batch land

    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 860}, device_scale_factor=2)
        page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        page.fill('input[autocomplete="username"]', "admin")
        page.fill('input[autocomplete="current-password"]', "shot-pass")
        page.click("button[type=submit]")
        page.wait_for_selector(".shell", timeout=20000)

        shots = [
            ("#/fleet",    "fleet.png"),
            ("#/execute",  "execute.png"),
            ("#/obs/services", "services.png"),
            ("#/obs/alerts",   "alerts.png"),
        ]
        for route, fname in shots:
            page.goto(f"http://127.0.0.1:{PORT}/{route}")
            page.wait_for_timeout(1600)
            # settle any spinner / let SSE land
            try:
                page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass
            page.wait_for_timeout(400)
            out = os.path.join(OUT, fname)
            page.screenshot(path=out, full_page=False)
            print(f"  saved {out}")

        # M8.1: seed a release in the store, then show the Releases tab.
        # (The server does not validate signature content on upload — a dummy
        # 64-byte signature is enough for the screenshot.)
        import base64
        try:
            curl("POST", "/updates/releases", {
                "version": "v0.9.0", "arch": "linux-amd64", "kind": "agent",
                "signature": base64.b64encode(bytes(range(64))).decode(),
                "artifact_b64": base64.b64encode(b"demo partout release artifact").decode(),
            }, token="shot-token")
        except Exception:
            pass
        page.goto(f"http://127.0.0.1:{PORT}/#/updates")
        page.wait_for_timeout(1200)
        page.click("div.tab:has-text('Releases')")
        page.wait_for_timeout(1200)
        out = os.path.join(OUT, "updates-releases.png")
        page.screenshot(path=out, full_page=False)
        print(f"  saved {out}")

        browser.close()
    print("screenshots done")
    sys.exit(0)
finally:
    if srv:
        try: srv.send_signal(signal.SIGTERM)
        except Exception: pass
    shutil.rmtree(WORK, ignore_errors=True)
