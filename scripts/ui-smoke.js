// Headless DOM smoke test for the embedded SPA. Driven by scripts/ui-smoke.sh,
// which boots a real embedded server, seeds data, and passes BASE + TOK here.
//
// It mounts the *real* app.js served by that server, logs in, walks every page,
// and asserts REAL data renders (not merely that nothing threw). This is the
// guard for the UI↔API contract: a loader reading the wrong response key or a
// template binding a field that does not exist blanks a page silently and no Go
// test notices.
const { JSDOM, VirtualConsole } = require("jsdom");
const nodeUtil = require("util"); // TextEncoder/Decoder shims for jsdom (real browsers have both)

const base = process.env.BASE || "http://localhost:18471";
const realFetch = global.fetch;
const token = process.env.TOK;

const failures = [];
function check(name, cond, extra) {
  console.log((cond ? "  PASS " : "  FAIL ") + name + (cond ? "" : "  <<< " + (extra || "")));
  if (!cond) failures.push(name);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rowsWithText = (d, text) =>
  [...d.querySelectorAll("table.tbl tr")].filter((tr) => tr.textContent.includes(text)).length;

async function main() {
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => console.log("  JSDOM ERROR:", e.message));
  vc.on("error", (...a) => console.log("  console.error:", ...a));

  const dom = await JSDOM.fromURL(base + "/", {
    runScripts: "dangerously",
    resources: "usable",
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      if (!window.TextDecoder) { window.TextDecoder = nodeUtil.TextDecoder; window.TextEncoder = nodeUtil.TextEncoder; }
      if (!window.Blob.prototype.arrayBuffer) {
        // Modern browsers have Blob.arrayBuffer; jsdom@24 does not.
        window.Blob.prototype.arrayBuffer = function () {
          return new Promise((resolve, reject) => {
            const fr = new window.FileReader();
            fr.onload = () => resolve(new Uint8Array(fr.result).buffer);
            fr.onerror = () => reject(fr.error);
            fr.readAsArrayBuffer(this);
          });
        };
      }
      window.fetch = (path, opts) => realFetch(new URL(String(path), base), opts);
      // No real SSE here; the app must render from its initial load alone.
      window.EventSource = class {
        constructor() { setTimeout(() => this.onopen && this.onopen(), 40); }
        close() {}
        addEventListener() {}
      };
      if (token) window.localStorage.setItem("partout_token", token);
    },
  });
  const w = dom.window, d = w.document;
  await sleep(3500);

  const visit = async (hash, ms = 1300) => { w.location.hash = hash; await sleep(ms); };

  check("shell mounted", !!d.querySelector(".shell"), "no .shell; body=" + d.body.innerHTML.length);
  check("logged in as admin", (d.querySelector(".uname") || {}).textContent === "admin");
  // Stale banner: simulating a stream drop (after a real connection) must
  // surface a warning + dim the data, so stale data isn't mistaken for live.
  if (w.__partout) {
    const inst = w.__partout;
    inst.sseWasConnected = true; inst.sseStatus = "reconnecting";
    await sleep(150);
    check("stale: banner on stream drop", !!d.querySelector(".stale-banner") && d.body.textContent.includes("Live updates paused"), "no stale banner");
    check("stale: data dimmed", !!d.querySelector(".body.sse-stale"), "data not dimmed on stale");
    inst.sseStatus = "connected"; await sleep(100); // restore
    check("stale: banner cleared on reconnect", !d.querySelector(".stale-banner"), "stale banner persists after reconnect");
  }
  // Sidebar brand shows the SERVER VERSION (fetched from /api/v1/version),
  // not the listen port.
  let srvVer = "";
  try { const j = await (await realFetch(base + "/api/v1/version")).json(); srvVer = j.version || ""; } catch (e) { srvVer = ""; }
  const brandPort = ((d.querySelector(".brand .port") || {}).textContent || "").trim();
  check("sidebar: server version in brand", srvVer !== "" && brandPort === srvVer, "brand=" + JSON.stringify(brandPort) + " expected=" + srvVer);
  const portEl = d.querySelector(".port");
  check("sidebar: brand version has data-tip", !!portEl && portEl.hasAttribute("data-tip"), "no data-tip on brand version");
  const sseDot = d.querySelector(".sse-dot");
  check("topbar: sse dot has data-tip", !!sseDot && sseDot.hasAttribute("data-tip"), "no data-tip on sse dot");

  // Global toast system: drive notify() and assert a toast renders.
  const inst = w.__partout;
  check("toasts: container renders", !!d.querySelector(".toasts"), "no .toasts container");
  if (inst && typeof inst.notify === "function") {
    const tid = inst.notify("ok", "smoke-toast-ok");
    await sleep(120);
    const t = [...d.querySelectorAll(".toast")].find((x) => x.textContent.includes("smoke-toast-ok"));
    check("toasts: notify() renders a toast", !!t && !!t.classList.contains("ok"), "no ok toast");
    inst.dismissToast(tid);
    await sleep(120);
    check("toasts: dismiss removes it", ![...d.querySelectorAll(".toast")].some((x) => x.textContent.includes("smoke-toast-ok")));
  } else {
    check("toasts: notify() available", false, "app instance not exposed");
  }

  await visit("#/fleet");
  check("fleet: host row", rowsWithText(d, "ag_") > 0);
  check("fleet: group scope rendered", !!d.querySelector(".nav-scope"));

  // Nav IA: grouped, collapsible sections ordered common → advanced.
  const navSections = [...d.querySelectorAll("nav.nav .nav-section")].map((s) => s.textContent.trim());
  check("nav: grouped sections (common→advanced)",
    navSections.join("|").includes("Fleet") && navSections.join("|").includes("Automation") &&
    navSections.join("|").includes("Observe") && navSections.join("|").includes("Governance") &&
    navSections.join("|").includes("Admin"),
    "sections=" + navSections.join("|"));
  check("nav: renamed Hosts item", [...d.querySelectorAll("nav.nav .nav-item")].some((x) => x.textContent.trim().endsWith("Hosts")), "no Hosts nav item");
  check("nav: palette button in topbar", !!d.querySelector(".palette-btn"), "no ⌘K button");
  if (w.__partout) {
    const jobsVisible = () => [...d.querySelectorAll("nav.nav .nav-item")].some((x) => x.textContent.includes("Jobs"));
    check("nav: automation items visible pre-collapse", jobsVisible(), "Jobs item missing");
    w.__partout.toggleNavGroup("automation");
    await sleep(250);
    check("nav: collapse hides section items", !jobsVisible(), "Jobs still visible after collapse");
    w.__partout.toggleNavGroup("automation");
    await sleep(250);
    check("nav: re-expand restores section items", jobsVisible(), "Jobs missing after re-expand");
  }

  // Scope: a role: group must resolve server-side (1 host) and filter the
  // fleet table — the old local host:-only regex showed the whole fleet.
  if (w.__partout) {
    w.__partout.setScope("roled");
    await sleep(1500);
    const hint = (d.querySelector(".nav-scope-hint") || {}).textContent || "";
    check("scope: role: selector resolves server-side", hint.includes("1 host(s) in scope"), "hint=" + hint);
    check("scope: fleet table filtered", ((d.querySelector(".page-sub") || {}).textContent || "").includes("1 host"), "sub=" + ((d.querySelector(".page-sub") || {}).textContent || ""));
    w.__partout.clearScope();
    await sleep(400);
  }

  // OS column + free-text fleet filter.
  const fleetHead = (d.querySelector("section thead") || {}).textContent || "";
  check("fleet: OS column", fleetHead.includes("OS"), "head=" + fleetHead);
  if (w.__partout) {
    w.__partout.fleetFilter = "zzz-no-match";
    await sleep(400);
    check("fleet: filter hides non-matching rows", d.querySelectorAll("section table.tbl tbody tr.click").length === 0, "rows still visible");
    check("fleet: filter empty-state", ((d.querySelector(".empty") || {}).textContent || "").includes("zzz-no-match"), "no filter empty-state");
    const hostname = ((w.__partout.hosts[0] || {}).hostname || "");
    if (hostname) {
      w.__partout.fleetFilter = hostname.slice(0, 4);
      await sleep(400);
      check("fleet: filter matches hostname", d.querySelectorAll("section table.tbl tbody tr.click").length === 1, "expected exactly 1 row");
    } else {
      check("fleet: filter matches hostname", false, "host has no hostname fact");
    }
    w.__partout.fleetFilter = "";
    await sleep(300);
  }

  // Add-host dialog: entry point, both tabs, real token mint -> command block.
  check("fleet: add-host entry", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("+ Add host")));
  if (w.__partout) {
    w.__partout.openAddHost();
    await sleep(250);
    check("add-host: dialog renders", !!d.querySelector(".overlay .dialog"));
    check("add-host: both tabs", [...d.querySelectorAll(".overlay .tab")].map((x) => x.textContent).join("|").includes("Run on the host") && [...d.querySelectorAll(".overlay .tab")].map((x) => x.textContent).join("|").includes("Onboard over SSH"));
    w.__partout.mintAddHostToken();
    await sleep(900);
    const cmd = (d.querySelector(".overlay .console") || {}).textContent || "";
    check("add-host: command embeds one-time token", cmd.includes("PARTOUT_TOKEN=par_enr_") && cmd.includes("--mode=agent"), "cmd=" + cmd.slice(0, 120));
    check("add-host: ttl countdown rendered", /expires in \d+ s/.test((d.querySelector(".overlay") || {}).textContent || ""));
    // fresh/join tooltips live in the SSH tab's select: switch tabs first.
    w.__partout.addHostTab = "ssh";
    await sleep(250);
    const optTitles = [...d.querySelectorAll(".overlay select option")].map((o) => o.getAttribute("title") || "").join("|");
    check("add-host: fresh/join tooltips", optTitles.includes("fresh: clean slate") && optTitles.includes("join: non-destructive"), "titles=" + optTitles);
    w.__partout.closeAddHost();
    await sleep(250);
    check("add-host: dialog closed", !d.querySelector(".overlay"));
  } else {
    check("add-host: app instance exposed", false, "no window.__partout");
  }

  // --- Getting-started checklist: shown on an empty fleet, dismissible ---
  // (already on #/fleet, so clearing hosts does not trigger a refetch)
  if (w.__partout) {
    const savedHosts = w.__partout.hosts;
    w.__partout.hosts = []; w.__partout.hostsLoading = false; w.__partout.gsDismissed = false;
    await sleep(250);
    check("fleet: getting-started on empty fleet", !!d.querySelector(".gs-card") && d.body.textContent.includes("Get started"), "checklist not shown on empty fleet");
    check("fleet: checklist primary CTA", [...d.querySelectorAll(".gs-primary button.btn.primary")].some((b) => b.textContent.includes("Start onboarding")), "primary onboarding CTA missing");
    w.__partout.dismissGettingStarted();
    await sleep(250);
    check("fleet: checklist dismissible", !d.querySelector(".gs-card"), "checklist still shown after dismiss");
    w.__partout.hosts = savedHosts;
    await sleep(250);
  }

  const hostId = (w.__partout && w.__partout.hosts && w.__partout.hosts[0] && w.__partout.hosts[0].id) ||
    [...d.querySelectorAll("table.tbl tr td .host-id")].map((t) => t.textContent.trim()).find((s) => s.startsWith("ag_"));
  check("fleet: host id resolvable", !!hostId, "no host id on the fleet page");
  await visit("#/host/" + hostId);
  const overview = d.querySelector("section");
  const ovText = overview ? overview.textContent : "";
  check("host overview: connected state", ovText.includes("connected"), "overview=" + ovText.slice(0, 160));
  check("host overview: version present", /0\.0\.0-dev|v\d/.test(ovText), "no version");
  check("host overview: EOL status rendered", /(supported|ending soon|end-of-life|unknown)/.test(ovText));
  check("host overview: EOL date rendered", /\d{4}-\d{2}-\d{2}/.test(ovText), "no YYYY-MM-DD date");

  // Labels & roles (operator surface): a saved display name must drive the
  // overview heading; a role added inline must render as a removable chip.
  check("host: labels card rendered", d.body.textContent.includes("Labels & roles"), "labels card missing");
  check("host: OS row in overview", [...d.querySelectorAll("section dt")].some((x) => x.textContent.trim() === "OS"), "no OS dt in overview kv");
  check("host: remove button (admin)", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Remove host")), "no Remove host button");
  if (w.__partout) {
    w.__partout.labelDraft.name = "smoke-web-01";
    w.__partout.saveHostLabels();
    await sleep(1500);
    check("host: saved display name in heading", (d.querySelector("section h2") || {}).textContent === "smoke-web-01", "h2=" + ((d.querySelector("section h2") || {}).textContent || ""));
    w.__partout.roleDraft = "smoke-role";
    w.__partout.addRole();
    await sleep(1500);
    check("host: role chip rendered", [...d.querySelectorAll(".chip")].some((c) => c.textContent.includes("smoke-role")), "no role chip");
  } else {
    check("host: app instance exposed", false, "no window.__partout");
  }

  await visit("#/host/" + hostId + "/facts");
  check("host facts: JSON console", !!d.querySelector(".console") && d.querySelector(".console").textContent.includes("{"));

  // Command palette: opens, filters, and jumps to a page.
  if (w.__partout) {
    w.__partout.openPalette();
    await sleep(350);
    check("palette: overlay renders", !!d.querySelector(".palette"), "no palette overlay");
    w.__partout.paletteQ = "audit";
    await sleep(350);
    const first = (w.__partout.paletteItems || [])[0];
    check("palette: query filters to Audit page", !!first && first.label === "Audit", "items=" + (w.__partout.paletteItems || []).map((x) => x.label).join("|"));
    w.__partout.paletteRun();
    await sleep(1300);
    check("palette: enter jumps to the page", w.location.hash === "#/audit", "hash=" + w.location.hash);
  } else {
    check("palette: app instance exposed", false, "no window.__partout");
  }

  await visit("#/execute");
  check("execute: run button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Run command")));

  await visit("#/audit");
  check("audit renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Audit"));

  await visit("#/sessions");
  check("sessions renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Sessions"));

  await visit("#/files", 1800);
  const fileRows = d.querySelectorAll("table.tbl tbody tr").length;
  check("files: real entries", fileRows > 2, "file rows=" + fileRows + " (400/empty => broken)");
  check("files: directory row", [...d.querySelectorAll("table.tbl tr")].some((tr) => tr.textContent.includes("📁")));
  // Browse into a directory that has regular files so a Download action renders.
  if (w.__partout) { w.__partout.fileDir = "/etc"; w.__partout.listFiles(); }
  await sleep(1200);
  check("files: download action", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Download")), "no Download button in /etc");
  // New file dialog: open a small real text file, assert stat + content +
  // CAS controls render; Save must stay disabled until the editor is dirty.
  check("files: + Upload button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("+ Upload")), "no + Upload button");
  if (w.__partout) { w.__partout.openFileDlg({ name: "hostname", is_dir: false }); }
  await sleep(1500);
  const dlg = [...d.querySelectorAll(".dialog.card")].find((x) => x.textContent.includes(": /etc/hostname"));
  check("files: dialog opens with stat meta", !!dlg && dlg.textContent.includes("sha256"), "no file dialog / no stat meta");
  const ta = dlg && dlg.querySelector("textarea");
  check("files: editor loaded real content", !!ta && ta.value.trim().length > 0, "textarea empty");
  const saveBtn = dlg && [...dlg.querySelectorAll("button")].find((b) => b.textContent.includes("Save (CAS)"));
  check("files: Save disabled until dirty", !!saveBtn && saveBtn.disabled, "Save not disabled on fresh load");
  if (ta) { ta.value += "\n# smoke-test\n"; ta.dispatchEvent(new w.window.Event("input", { bubbles: true })); }
  await sleep(150);
  check("files: Save enables on edit", !!saveBtn && !saveBtn.disabled, "Save still disabled after edit");
  if (w.__partout) { w.__partout.fileDlg.open = false; }
  await sleep(200);
  // End-to-end upload: ship a real file to /tmp on the local agent (driving
  // the confirm dialog like a user), verify the listing shows it, then open
  // it in the dialog and verify the content round-trips.
  if (w.__partout) {
    w.__partout.openUpDlg();
    w.__partout.upDlg.file = new w.window.File([new w.window.TextEncoder().encode("partout-smoke-upload\n")], "smoke-upload.txt");
    w.__partout.upDlg.path = "/tmp/smoke-upload.txt";
    w.__partout.upDlgGo();
  }
  await sleep(300);
  const upConfirm = [...d.querySelectorAll(".dialog.card button")].find((b) => b.textContent.trim() === "Upload" && b.closest(".dialog.card").textContent.includes("Overwrites"));
  if (upConfirm) upConfirm.click();
  await sleep(1800);
  // Navigate to /tmp and reload so the listing actually shows the new file
  // (upDlgGo re-lists the current dir, which was /etc).
  if (w.__partout) { w.__partout.fileDir = "/tmp"; w.__partout.listFiles(); }
  await sleep(1200);
  check("files: upload round-trips to disk", [...d.querySelectorAll("table.tbl tbody tr")].some((tr) => tr.textContent.includes("smoke-upload.txt")), "uploaded row missing in listing");
  if (w.__partout) {
    w.__partout.openFileDlg({ name: "smoke-upload.txt", is_dir: false });
  }
  await sleep(1500);
  const upDlg2 = [...d.querySelectorAll(".dialog.card")].find((x) => x.textContent.includes(": /tmp/smoke-upload.txt"));
  const ta2 = upDlg2 && upDlg2.querySelector("textarea");
  check("files: uploaded content round-trips", !!ta2 && ta2.value === "partout-smoke-upload\n", "content mismatch: " + (ta2 ? JSON.stringify(ta2.value) : "no textarea"));
  // Edit-CAS round-trip: modify in the (still open) dialog, save via the
  // confirm dialog, then close/reopen and verify persistence; afterwards
  // force a stale baseline and verify the 409 conflict surfaces in the
  // dialog instead of a silent clobber.
  if (ta2) { ta2.value = "partout-smoke-edit\n"; ta2.dispatchEvent(new w.window.Event("input", { bubbles: true })); }
  await sleep(150);
  const saveBtn2 = upDlg2 && [...upDlg2.querySelectorAll("button")].find((b) => b.textContent.includes("Save (CAS)"));
  if (saveBtn2) saveBtn2.click();
  await sleep(300);
  const saveConfirm = [...d.querySelectorAll(".dialog.card button")].find((b) => b.textContent.trim() === "Save" && b.closest(".dialog.card").textContent.includes("Aborts if the file changed"));
  if (saveConfirm) saveConfirm.click();
  await sleep(1800);
  if (w.__partout) { w.__partout.fileDlg.open = false; await sleep(100); w.__partout.openFileDlg({ name: "smoke-upload.txt", is_dir: false }); }
  await sleep(1500);
  const dlg3 = [...d.querySelectorAll(".dialog.card")].find((x) => x.textContent.includes(": /tmp/smoke-upload.txt"));
  const ta3 = dlg3 && dlg3.querySelector("textarea");
  check("files: CAS edit round-trips to disk", !!ta3 && ta3.value === "partout-smoke-edit\n", "edit not persisted: " + (ta3 ? JSON.stringify(ta3.value) : "no textarea"));
  if (w.__partout && ta3) {
    w.__partout.fileDlg.origSha = "0000000000000000000000000000000000000000000000000000000000000000"; // stale baseline → must 409
    ta3.value += "x\n"; ta3.dispatchEvent(new w.window.Event("input", { bubbles: true }));
  }
  await sleep(150);
  const saveBtn3 = [...d.querySelectorAll(".dialog.card button")].find((b) => b.textContent.includes("Save (CAS)"));
  if (saveBtn3) saveBtn3.click();
  await sleep(300);
  const saveConfirm2 = [...d.querySelectorAll(".dialog.card button")].find((b) => b.textContent.trim() === "Save" && b.closest(".dialog.card").textContent.includes("Aborts if the file changed"));
  if (saveConfirm2) saveConfirm2.click();
  await sleep(1500);
  check("files: stale CAS rejected with conflict", (w.__partout.fileDlg.err || "").includes("Conflict"), "no conflict surfaced: " + (w.__partout.fileDlg.err || ""));
  if (w.__partout) { w.__partout.fileDlg.open = false; }
  await sleep(200);

  await visit("#/jobs");
  check("jobs: job name", rowsWithText(d, "nightly df") > 0, "no job row");
  check("jobs: task column", rowsWithText(d, "task_task_") > 0, "task column empty");
  check("jobs: new job button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("New job")), "no New job button");
  check("jobs: edit/runs/delete actions", [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Edit") && [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Runs") && [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Delete"), "job actions missing");
  // Row-level dispatch feedback: run the seeded job (single embedded host —
  // no prompt) and assert the outcome lands in a note row under the affected
  // job, not only in a global toast. Then dismiss it.
  if (w.__partout) {
    const j = w.__partout.jobs.find((x) => x.name === "nightly df");
    if (!j) { check("jobs: seeded job for dispatch", false, "nightly df not in jobs list"); }
    else {
      // Slow the API round-trip so the busy window (and the row spinner)
      // is observable — the embedded server otherwise answers faster than
      // the harness can assert.
      const origApi = w.__partout.api.bind(w.__partout);
      w.__partout.api = async (path, opts) => { await sleep(700); return origApi(path, opts); };
      const p = w.__partout.runJob(j);
      await sleep(300);
      check("jobs: dispatch spinner on the row", [...d.querySelectorAll("button .spin")].some((s) => s.closest("button") && s.closest("button").textContent.includes("Run now")), "no spinner on Run now while busy");
      await p;
      w.__partout.api = origApi;
      await sleep(300);
      const note = [...d.querySelectorAll("tr")].find((tr) => tr.classList.contains("row-note"));
      check("jobs: dispatch outcome on the affected row", !!note && /Run started on|parked on approval/.test(note.textContent), "row note missing: " + (note ? note.textContent.slice(0, 80) : "none"));
      const dismiss = note && [...note.querySelectorAll("button")].find((b) => b.textContent.trim() === "Dismiss");
      if (dismiss) dismiss.click();
      await sleep(200);
      check("jobs: dispatch note dismissable", ![...d.querySelectorAll("tr")].some((tr) => tr.classList.contains("row-note")), "note not dismissed");
    }
  }

  await visit("#/tasks");
  check("tasks: name", rowsWithText(d, "check disk") > 0, "task name missing");
  check("tasks: description", rowsWithText(d, "df -h") > 0, "task description missing");
  check("tasks: playbooks card", d.body.textContent.includes("Playbooks"));
  check("tasks: run action", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Run")), "no Run button");
  // Row-level dispatch feedback for tasks: same note-row pattern as jobs.
  if (w.__partout) {
    const t = w.__partout.tasks.find((x) => x.name === "check disk");
    if (!t) { check("tasks: seeded task for dispatch", false, "check disk not in tasks list"); }
    else {
      await w.__partout.runTask(t); await sleep(300);
      const note = [...d.querySelectorAll("tr")].find((tr) => tr.classList.contains("row-note"));
      check("tasks: dispatch outcome on the affected row", !!note && /Started on|parked on approval/.test(note.textContent), "row note missing: " + (note ? note.textContent.slice(0, 80) : "none"));
      if (note) { const dd = [...note.querySelectorAll("button")].find((b) => b.textContent.trim() === "Dismiss"); if (dd) dd.click(); }
      await sleep(200);
    }
  }
  check("tasks: recent runs card", d.body.textContent.includes("Recent task runs"), "runs card missing");
  check("tasks: new-task create button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Create…")), "no New task button");

  await visit("#/updates", 1800);
  check("updates renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Updates"));
  check("updates: apply button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Apply")), "no Apply button");
  // Stage 1: real selection — header checkbox + Sel. all / Sel. security
  // buttons replace the hand-typed package list as the primary path.
  const updTable = [...d.querySelectorAll("table.tbl")].find((t) => t.querySelector("th") && t.querySelector("th").nextElementSibling && t.querySelector("th").nextElementSibling.textContent === "Package");
  const selAllBtn = [...d.querySelectorAll("button")].find((b) => b.textContent.trim() === "Sel. all");
  const selSecBtn = [...d.querySelectorAll("button")].find((b) => b.textContent.trim() === "Sel. security");
  check("updates: selection controls (Sel. all / Sel. security)", !!updTable && !!selAllBtn && !!selSecBtn, "selection controls missing");
  const rowChecks0 = updTable ? [...updTable.querySelectorAll("tbody tr td input[type=checkbox]")] : [];
  // The agent's package backend is selected from the host.distro FACT, which
  // lands a moment after enrollment on a fresh server; until then the list
  // is legitimately empty (noop backend). Poll briefly for real rows so the
  // interaction checks run where data exists.
  let rowChecks = rowChecks0;
  for (let i = 0; i < 15 && !rowChecks.length; i++) {
    await sleep(1000);
    if (w.__partout) { await w.__partout.loadUpdates(); }
    rowChecks = updTable ? [...updTable.querySelectorAll("tbody tr td input[type=checkbox]")] : [];
  }
  if (rowChecks.length) {
    rowChecks[0].click();
    check("updates: row checkbox toggles model", Object.keys(w.__partout.pkgChecked).length === 1, "pkgChecked not updated on row click");
    selAllBtn.click();
    check("updates: Sel. all checks every row", Object.keys(w.__partout.pkgChecked).length === rowChecks.length, "Sel. all did not check all rows");
    selSecBtn.click(); // leave a deterministic state for later checks
  }
  check("updates: package actions card", d.body.textContent.includes("Package actions"), "actions card missing");
  check("updates: EOL data status + refresh", d.body.textContent.includes("EOL data:") && [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Refresh EOL data")), "ext-data controls missing");
  check("updates: EOL status has data-tip", !!d.querySelector(".ext-status[data-tip]"), "no data-tip on ext-status");

  // M5.1: fleet CVE security scan card + "Scan now" (real apt/dnf list +
  // OSV correlation in the harness; assert a host row appears, not which
  // CVEs — that depends on the box's real package state).
  check("updates: security card", d.body.textContent.includes("unpatched CVEs"), "security card missing");
  const scanBtn = [...d.querySelectorAll("button")].find((b) => b.textContent.trim() === "Scan now");
  check("updates: Scan now button", !!scanBtn, "Scan now missing");
  if (scanBtn) {
    scanBtn.click();
    let scanned = false;
    for (let i = 0; i < 90 && !scanned; i++) {
      await sleep(1000);
      if (w.__partout) scanned = (w.__partout.security || []).length > 0;
    }
    check("updates: security scan produced a host row", scanned, "no scan row after 90s");
    // Stage 2: fleet patching — "Patch all security" is always present for
    // operators (disabled without findings); per-host "Patch" appears when
    // a host actually has CVE findings.
    check("updates: Patch all security button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Patch all security")), "Patch all security missing");
    const findings = (w.__partout.security || []).some((s) => (s.findings || []).length);
    const patchBtns = [...d.querySelectorAll("button")].filter((b) => b.textContent.trim() === "Patch");
    check("updates: per-host Patch buttons match findings", findings ? patchBtns.length >= 1 : patchBtns.length === 0, findings ? "expected per-host Patch buttons" : "unexpected Patch buttons");
  }
  // M8.1 release store: upload a signed release via the API, then show the
  // Releases tab.
  {
    const nodeCrypto = require("crypto");
    const { privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
    const artifact = Buffer.from("smoke release artifact bytes");
    const sha = nodeCrypto.createHash("sha256").update(artifact).digest("hex");
    const manifest = ["0.9.0-smoke", "linux-amd64", "agent", sha].join("|");
    const sig = nodeCrypto.sign(null, Buffer.from(manifest), privateKey).toString("base64");
    const up = await realFetch(base + "/api/v1/updates/releases", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ version: "0.9.0-smoke", arch: "linux-amd64", kind: "agent", signature: sig, artifact_b64: artifact.toString("base64") }),
    });
    check("releases: signed upload via API", up.status === 201, "status=" + up.status);
  }
  const relTab = [...d.querySelectorAll(".tab")].find((t) => t.textContent.trim() === "Releases");
  check("updates: Packages/Releases tabs", !!relTab, "Releases tab missing");
  if (relTab) { relTab.click(); await sleep(600); }
  check("releases: uploaded row renders", rowsWithText(d, "0.9.0-smoke") > 0, "no release row");
  check("releases: upload form", d.body.textContent.includes("Upload a release"), "upload form missing");
  // An unsigned release uploads while the opt-in flag
  // (PARTOUT_ALLOW_UNSIGNED_RELEASES=true) is on, labelled in the Trust column.
  {
    const nodeCrypto = require("crypto");
    const artifact = Buffer.from("smoke UNSIGNED artifact bytes");
    const sha = nodeCrypto.createHash("sha256").update(artifact).digest("hex");
    const up = await realFetch(base + "/api/v1/updates/releases", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ version: "0.9.1-smoke", arch: "linux-amd64", kind: "agent", signature: "", artifact_b64: artifact.toString("base64") }),
    });
    check("releases: unsigned upload via API (opt-in flag on)", up.status === 201, "status=" + up.status);
    if (w.__partout) { w.__partout.loadReleases(); await sleep(500); }
  }
  {
    const okBadge = [...d.querySelectorAll(".badge.ok")].some((b) => b.textContent.trim() === "signed");
    const warnBadge = [...d.querySelectorAll(".badge.warn")].some((b) => b.textContent.trim() === "unsigned");
    check("releases: trust column + badges", d.body.textContent.includes("Trust") && okBadge && warnBadge, "trust column or badges missing");
    check("releases: unsigned badge has data-tip", !!d.querySelector(".badge.warn[data-tip]"), "no data-tip on unsigned badge");
  }
  // M8.1 step 3: rollout runs tab. Start a run at the smoke release via the
  // API; the embedded agent (no release key) refuses, so the run lands on
  // paused_failure — a real live state to assert.
  const runsTab = [...d.querySelectorAll(".tab")].find((t) => t.textContent.trim() === "Runs");
  check("updates: Runs tab", !!runsTab, "Runs tab missing");
  if (runsTab) { runsTab.click(); await sleep(600); }
  check("runs: new-rollout form", d.body.textContent.includes("New rollout"), "rollout form missing");
  let smokeRunId = "";
  {
    const rels = await (await realFetch(base + "/api/v1/updates/releases", { headers: { Authorization: "Bearer " + token } })).json();
    const rel = rels.items.find((r) => r.version === "0.9.0-smoke");
    const runRes = await realFetch(base + "/api/v1/updates/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ release_id: rel.id, selector: "all", canary: 0, wave_pct: 100 }),
    });
    check("runs: create via API", runRes.status === 201, "status=" + runRes.status);
    if (runRes.status === 201) smokeRunId = (await runRes.json()).run_id;
  }
  // Let the server FSM tick: dispatch -> agent refusal (no release key in
  // the harness) -> paused_failure. Poll the real API for the state.
  let smokeRunStatus = "";
  for (let i = 0; i < 30 && smokeRunStatus !== "paused_failure"; i++) {
    await sleep(500);
    try {
      const rr = await (await realFetch(base + "/api/v1/updates/runs/" + smokeRunId, { headers: { Authorization: "Bearer " + token } })).json();
      smokeRunStatus = rr.run.status;
    } catch (e) { /* not ready yet */ }
  }
  check("runs: FSM reached paused_failure (live)", smokeRunStatus === "paused_failure", "status=" + smokeRunStatus);
  // The harness stubs SSE by design; drive the same refresh it would.
  if (w.__partout) { w.__partout.loadRuns(); w.__partout.openRun(smokeRunId); }
  await sleep(700);
  check("runs: run row renders", rowsWithText(d, "0.9.0-smoke") > 0, "no run row");
  check("runs: paused_failure badge", d.body.textContent.includes("paused_failure"), "status badge missing");
  check("runs: per-host failed_rollback row", d.body.textContent.includes("failed_rollback"), "host state missing");

  // M8.1.1: each agent-release upload pre-armed a PARKED draft rollout.
  // The board shows the drafts with a Start button. Start the SIGNED
  // release's draft: the keyless harness agent refuses it (no release key),
  // so the run goes live and fails safely — no swap. (Never start the
  // unsigned one: with the opt-in flag on, a keyless agent accepts
  // unsigned releases and would swap to the fake artifact.)
  const draftRows = [...d.querySelectorAll("tbody tr")].filter((tr) => {
    const badge = tr.querySelector(".badge");
    return badge && badge.textContent.trim() === "draft";
  });
  check("runs: auto-draft rows for the uploaded releases", draftRows.length >= 2, "draft rows=" + draftRows.length);
  const v90 = draftRows.find((tr) => tr.textContent.includes("0.9.0-smoke"));
  check("runs: draft row for the signed release", !!v90, "no 0.9.0-smoke draft row");
  if (v90) {
    const startBtn = [...v90.querySelectorAll("button")].find((b) => b.textContent.trim() === "Start");
    check("runs: draft Start button", !!startBtn, "Start button missing");
    if (startBtn) {
      startBtn.click();
      let draftStatus = "draft";
      for (let i = 0; i < 10 && draftStatus === "draft"; i++) {
        await sleep(400);
        try {
          const runs = await (await realFetch(base + "/api/v1/updates/runs", { headers: { Authorization: "Bearer " + token } })).json();
          const dr = (runs.items || []).find((r) => r.version === "0.9.0-smoke" && r.status === "draft");
          draftStatus = dr ? "draft" : "live";
        } catch (e) { /* not ready yet */ }
      }
      check("runs: started draft left the draft state (live)", draftStatus !== "draft", "still draft");
    }
  }

  await visit("#/secrets");
  check("secrets: row rendered", rowsWithText(d, "dbpass") > 0, "secret not rendered");
  check("secrets: create form", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Create secret")), "no Create secret button");
  check("secrets: rotate action", [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Rotate"), "no Rotate button");

  await visit("#/policies");
  check("policies: name", rowsWithText(d, "deny-rm") > 0, "policy name missing");
  check("policies: match chip", rowsWithText(d, "command_regex") > 0, "match not rendered");
  // Fleet-management preset (first-boot defaults): panel renders, a fresh
  // server has every default present, deleting one is detected, and
  // "Apply missing" restores it (idempotent re-apply).
  check("policies: preset panel", d.body.textContent.includes("Fleet defaults (preset)"), "preset card missing");
  if (w.__partout && w.__partout.presetStatus) {
    check("policies: preset defaults all present on a fresh server", w.__partout.presetMissing === 0, "missing=" + w.__partout.presetMissingList);
    const row = ((w.__partout.presetStatus.policies) || [])[0];
    if (row) {
      await realFetch(base + "/api/v1/policies/" + row.id, { method: "DELETE", headers: { Authorization: "Bearer " + token } });
      w.__partout.loadPreset();
      await sleep(500);
      check("policies: deleted default detected as missing", w.__partout.presetMissing >= 1, "missing=" + w.__partout.presetMissing);
      w.__partout.applyPreset();
      await sleep(900);
      check("policies: apply missing restores the default", w.__partout.presetMissing === 0, "still missing=" + w.__partout.presetMissingList);
    }
  } else {
    check("policies: preset status exposed", false, "no window.__partout.presetStatus");
  }

  await visit("#/approvals");
  check("approvals: page renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Approvals"));
  check("approvals: pending request row", rowsWithText(d, "apr_") > 0, "no approval row");
  check("approvals: agent on the row (friendly name)", rowsWithText(d, (w.__partout.hosts[0] || {}).name || (w.__partout.hosts[0] || {}).hostname || "ag_") > 0, "agent missing");
  check("approvals: approve button (admin)", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Approve")), "no Approve button");
  check("approvals: pending badge", !!d.querySelector(".badge.warn") && d.querySelector(".badge.warn").textContent.includes("pending"), "no pending badge");

  await visit("#/mcp");
  check("mcp: page renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("MCP"));
  check("mcp: http endpoint", rowsWithText(d, "/mcp") > 0, "endpoint missing");
  check("mcp: run_command tool row", rowsWithText(d, "run_command") > 0, "tool row missing");
  check("mcp: write badge", rowsWithText(d, "write") > 0, "no write badge");
  check("mcp: mcp.json snippet", d.body.textContent.includes("mcpServers"), "snippet missing");
  check("mcp: identity write tools", (d.body.textContent.match(/set_host_tag|add_host_role|delete_host/g) || []).length >= 3, "new identity tools missing");
  check("mcp: oauth2 clients card", d.body.textContent.includes("OAuth2 clients"), "clients card missing");

  await visit("#/users");
  check("users: admin + alice", rowsWithText(d, "admin") > 0 && rowsWithText(d, "alice") > 0, "users missing");
  check("users: create form", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Create user")), "no Create user button");
  check("users: role selector + disable", [...d.querySelectorAll("select")].length > 0 && [...d.querySelectorAll("button")].some((b) => ["Disable", "Enable"].includes(b.textContent.trim())), "role/disable controls missing");

  await visit("#/provision");
  check("provision: new-run card", d.body.textContent.includes("New run"), "new-run card missing");
  check("provision: seeded run row", rowsWithText(d, "nobody@127.0.0.1") > 0, "run row missing");
  check("provision: fingerprint column", d.body.textContent.includes("Key fingerprint"), "fingerprint column missing");
  check("provision: started column", d.body.textContent.includes("Started") && /(now|\d+\w+ ago)/.test(d.body.textContent), "Started column or relative time missing");
  {
    // Clicking a run must expand the step detail INLINE, directly under that
    // row (not in a block after the table).
    const trs = [...d.body.querySelectorAll("section table.tbl tbody tr")];
    const row = trs.find((tr) => tr.textContent.includes("nobody@127.0.0.1"));
    if (row) { row.click(); await sleep(900); }
    const after = [...d.body.querySelectorAll("section table.tbl tbody tr")];
    const iRow = after.findIndex((tr) => tr.textContent.includes("nobody@127.0.0.1"));
    const inline = iRow >= 0 && after[iRow + 1] && after[iRow + 1].querySelector(".prov-inline");
    check("provision: inline step detail under row", !!inline && d.body.textContent.includes("Output excerpt"), "step detail not rendered directly below the clicked row");
  }
  // A finished run whose agent linked in must show the host's LIVE state
  // (run state is a past-tense snapshot) and link to the host page.
  if (w.__partout) {
    const inst = w.__partout;
    const now = Math.floor(Date.now() / 1000);
    inst.hosts = [...inst.hosts, { id: "ag_smokechip", name: "smoke-chip", state: "connected", last_seen: now }];
    inst.provRuns = [...inst.provRuns, { id: "pr_smokechip", host: "chip@127.0.0.1", mode: "join", state: "connected", agent_id: "ag_smokechip", created: now }];
    await sleep(400);
    const row = [...d.body.querySelectorAll("table.tbl tbody tr")].find((tr) => tr.textContent.includes("pr_smokechip"));
    const chip = row && [...row.querySelectorAll("a.badge")].find((a) => a.textContent.trim() === "connected");
    check("provision: live host chip on connected run", !!chip, "no host state chip on the connected run row");
    if (chip) { chip.click(); await sleep(900); }
    check("provision: chip navigates to host page", String(w.location.hash).includes("ag_smokechip"), "hash=" + w.location.hash);
    inst.hosts = inst.hosts.filter((h) => h.id !== "ag_smokechip");
    inst.provRuns = inst.provRuns.filter((r) => r.id !== "pr_smokechip");
    await visit("#/provision");
  }

  if (w.__partout) {
    const inst = w.__partout;
    // key_confirm (host-key TOFU gate) must be discoverable from anywhere:
    // the SSE event fires a global warn toast (the run parks there until an
    // admin acts — nothing else moves it), and the nav shows a badge for
    // each run parked at the gate.
    inst.onSSEEvent("provision.key_confirm", { run_id: "prv_smoke_kc", host: "smoke@key", key_type: "ED25519", fingerprint: "SHA256:smokefingerprint" });
    await sleep(400);
    check("provision: key_confirm toast fires on any page", d.body.textContent.includes("awaits host-key confirmation"), "no key_confirm toast");
    inst.navBadges.provision = 2; // badge render wiring; the count itself comes from /provision-runs in loadNavBadges
    await sleep(300);
    const provBadge = [...d.querySelectorAll(".nav-badge")].find((b) => b.textContent.trim() === "2");
    check("provision: nav badge counts key_confirm runs", !!provBadge, "no nav badge for pending key confirmations");
    inst.navBadges.provision = 0;
    await sleep(200);
  }

  if (w.__partout) {
    const inst = w.__partout;
    // --- Onboarding wizard: target -> confirm -> live (deterministic, no SSH) ---
    await visit("#/provision");
    const startBtn = [...d.querySelectorAll("button")].find((b) => b.textContent.includes("Start onboarding"));
    check("provision: guided onboarding entry", !!startBtn, "no 'Start onboarding' button");
    if (startBtn) { startBtn.click(); await sleep(300); }
    check("wizard: target phase", d.body.textContent.includes("Step 1 of 3") && d.body.textContent.includes("Onboard a host"), "target phase not shown");
    check("wizard: host input + continue", !!d.querySelector("input[placeholder='user@host']") && [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Continue"), "host input or Continue missing");
    // Mode guidance: the selected mode's hint is shown (fresh default).
    check("wizard: mode hint shown", d.body.textContent.includes("clean slate") || d.body.textContent.includes("non-destructive"), "mode hint missing");
    // Already-enrolled hint: target a host that matches an enrolled one.
    const enrolledName = (inst.hosts[0] && (inst.hosts[0].hostname || inst.hosts[0].name)) || "";
    if (enrolledName) {
      inst.provWiz.host = "root@" + enrolledName; inst.provWiz.mode = "fresh";
      await sleep(150);
      check("wizard: already-enrolled warning (fresh)", d.body.textContent.includes("looks already enrolled"), "no already-enrolled hint");
      inst.provWiz.mode = "join";
      await sleep(150);
      check("wizard: join hint for enrolled host", /in place, preserving its identity/.test(d.body.textContent), "no join hint");
      inst.provWiz.host = "smoke@127.0.0.1"; inst.provWiz.mode = "fresh"; // restore for the rest
    }
    // advance to confirm
    inst.openProvWizard(); inst.provWiz.host = "smoke@127.0.0.1"; inst.provWizNext();
    await sleep(200);
    check("wizard: confirm phase + plan", d.body.textContent.includes("Step 2 of 3") && d.body.textContent.includes("Start provisioning"), "confirm phase not shown");
    check("wizard: five-step plan listed", /connect → preflight → transfer → install → wait-enroll/.test(d.body.textContent), "step plan not shown");
    // SSH access row: let the real fetch settle, then assert each render path
    // with a known value (deterministic — independent of the box's real keys).
    await sleep(400); // let provWizLoadSSH's real fetch settle
    inst.provWiz.phase = "confirm"; inst.provWiz.sshBusy = false;
    inst.provWiz.sshStatus = { ssh_dir: "/smoke/ssh", file_keys: ["id_ed25519"], agent: false };
    await sleep(150);
    check("wizard: ssh access row (file key)", d.body.textContent.includes("/smoke/ssh/id_ed25519") && d.body.textContent.includes("conventional key found"), "file-key row not shown");
    inst.provWiz.sshStatus = { ssh_dir: "/smoke/ssh", file_keys: [], agent: true };
    await sleep(150);
    check("wizard: ssh access row (agent)", d.body.textContent.includes("ssh-agent"), "agent row not shown");
    inst.provWiz.sshStatus = { ssh_dir: "/smoke/ssh", file_keys: [], agent: false };
    await sleep(150);
    check("wizard: ssh access row (none found)", d.body.textContent.includes("no identity key found"), "none-found row not shown");
    // inject a key_confirm live run -> fingerprint panel with Confirm/Deny
    inst.provWiz.phase = "live"; inst.provWiz.runId = "pr_wiz";
    inst.provWiz.run = { id: "pr_wiz", host: "smoke@127.0.0.1", mode: "fresh", state: "key_confirm", key_type: "ssh-ed25519", fingerprint: "SHA256:WIZFINGERPRINT123", step: "connect", created: 0, updated: 0 };
    inst.provWiz.steps = [{ seq: 1, name: "connect", state: "running" }];
    await sleep(250);
    check("wizard: live phase state badge", d.body.textContent.includes("Step 3 of 3"), "live phase not shown");
    check("wizard: fingerprint shown", d.body.textContent.includes("SHA256:WIZFINGERPRINT123"), "fingerprint not shown");
    check("wizard: confirm/deny actions", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Confirm key")) && [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Deny"), "Confirm/Deny missing");
    // terminal connected -> host enrolled + link
    inst.provWiz.run = { ...inst.provWiz.run, state: "connected", agent_id: "ag_wiz" };
    await sleep(200);
    check("wizard: enrolled result + host link", d.body.textContent.includes("Host enrolled.") && d.body.textContent.includes("ag_wiz"), "enrolled result not shown");
    inst.provWizClose();
    await sleep(200);
    check("wizard: closed", !d.body.textContent.includes("Step 1 of 3"), "wizard did not close");
  }

  await visit("#/obs-services", 1600);
  check("observe services: real unit",
    [...d.querySelectorAll("table.tbl tr")].some((tr) => /\.service|acme-serve|ssh|snap/.test(tr.textContent)),
    "no service rows");
  check("observe services: restarts column", d.body.textContent.includes("Restarts"), "no Restarts column");
  check("observe services: exit+cpu columns", d.body.textContent.includes("Exit") && d.body.textContent.includes("CPU"), "Exit/CPU columns missing");
  // Vendor-only units (no file in /etc/systemd/system) appear when named in
  // PARTOUT_SERVICE_LABELS (the harness sets it to 'cron'); stopped units
  // (state=inactive) are collected too and filterable via the state facet.
  const svcNames = w.__partout.services.map((r) => r.unit.name);
  check("services: labeled vendor unit shown", svcNames.includes("cron"), "cron missing from: " + svcNames.slice(0, 20).join(","));
  check("services: stopped units collected", w.__partout.services.some((r) => r.unit.state === "inactive"), "no inactive units listed");
  check("services: state facet includes inactive", (w.__partout.svcFacets.state || []).includes("inactive"), "inactive not in state facet");
  // Header filters: a dropdown per filterable column, options = values
  // actually present, combined with AND.
  check("services: header filter dropdowns", d.querySelectorAll("table.tbl thead select").length >= 4, "no header selects");
  const totalSvc = w.__partout.services.length;
  const firstSvc = w.__partout.services[0];
  w.__partout.svcF.unit = firstSvc.unit.name;
  await sleep(200);
  const nameRows = w.__partout.svcRows;
  check("services: unit name filter", nameRows.length >= 1 && nameRows.every((r) => r.unit.name === firstSvc.unit.name), "unit filter broken");
  w.__partout.svcF.state = firstSvc.unit.state;
  await sleep(200);
  const andRows = w.__partout.svcRows;
  check("services: filters combine with AND", andRows.length <= nameRows.length && andRows.every((r) => r.unit.name === firstSvc.unit.name && r.unit.state === firstSvc.unit.state), "AND combine broken");
  check("services: clear button appears", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Clear filters")), "no Clear filters button");
  if (w.__partout.svcFacets.state.length > 1) {
    const otherState = w.__partout.svcFacets.state.find((st) => st !== firstSvc.unit.state);
    w.__partout.svcF.host = firstSvc.host_id; // pin host: this unit's state is known
    w.__partout.svcF.state = otherState;
    await sleep(200);
    check("services: cross-state AND yields empty state", w.__partout.svcRows.length === 0 && d.body.textContent.includes("No units match the current filters"), "expected empty filtered state");
    w.__partout.svcF.host = "";
    await sleep(150);
  }
  w.__partout.svcClearF();
  await sleep(200);
  check("services: clear restores all rows", w.__partout.svcRows.length === totalSvc, "clear did not restore");
  // Action bar: the filtered set converts into a host selector.
  w.__partout.svcF.unit = firstSvc.unit.name;
  await sleep(200);
  check("services: action bar shows target", [...d.querySelectorAll("code")].some((c) => c.textContent.trim() === "all"), "target selector not shown");
  w.__partout.svcGroupName = "smoke-svc-group";
  await sleep(250); // let Vue re-render :disabled before clicking
  const saveGroupBtn = [...d.querySelectorAll("button")].find((b) => b.textContent.includes("Save group"));
  if (saveGroupBtn) saveGroupBtn.click();
  await sleep(700);
  check("services: group saved (input cleared)", w.__partout.svcGroupName === "", "group save did not complete");
  // Host filter pins the target; New alert jumps to Alerts with the rule form pre-filled.
  w.__partout.svcF.host = firstSvc.host_id;
  await sleep(200);
  check("services: host filter pins target", [...d.querySelectorAll("code")].some((c) => c.textContent.trim() === "host:" + firstSvc.host_id), "target not pinned to host");
  const newAlertBtn = [...d.querySelectorAll("button")].find((b) => b.textContent.includes("New alert"));
  if (newAlertBtn) newAlertBtn.click();
  await sleep(1500);
  check("alerts: rule pre-filled from services filter", w.__partout.page === "obs-alerts" && w.__partout.ruleForm && w.__partout.ruleForm.selector === "host:" + firstSvc.host_id, "ruleForm not prefilled: " + JSON.stringify(w.__partout.ruleForm && { sel: w.__partout.ruleForm.selector, kind: w.__partout.ruleForm.kind }));
  w.__partout.ruleForm = null;
  w.__partout.svcF = { unit: "", host: "", state: "", enabled: "", exit: "", restart: "", label: "" };
  w.__partout.go("obs-services");
  await sleep(900);
  // Viewer sees the read-only half of the action bar: target + Copy, but no
  // group/alert controls (they render only for operators) — the gate the
  // template uses is isOperator, so flip the role to exercise it.
  const adminRole = w.__partout.me && w.__partout.me.role;
  if (w.__partout.me) w.__partout.me.role = "viewer";
  w.__partout.svcF.unit = firstSvc.unit.name;
  await sleep(300);
  check("services: viewer target is read-only", [...d.querySelectorAll("code")].some((c) => c.textContent.trim() === "all") && !d.body.textContent.includes("save as group"), "viewer still sees group controls");
  check("services: viewer sees the operator-role note", d.body.textContent.includes("needs the operator role"), "no role note for viewer");
  if (w.__partout.me && adminRole) w.__partout.me.role = adminRole;
  w.__partout.svcClearF();
  await sleep(200);
  // Row click expands the detail row (description/pid/fragment/last-start).
  const svcRowEl = d.querySelector("table.tbl tbody tr");
  if (svcRowEl) svcRowEl.click();
  await sleep(300);
  check("observe services: detail row expands", d.body.textContent.includes("State —") || d.body.textContent.includes("Main PID") || d.body.textContent.includes("Unit file"), "no detail fields after row click");
  if (svcRowEl) svcRowEl.click();
  await sleep(200);
  await visit("#/obs-certs", 1600);
  check("observe certs: real cert",
    [...d.querySelectorAll("table.tbl tr")].some((tr) => tr.textContent.includes("CN =")), "no cert rows");
  check("observe certs: used-by column", d.body.textContent.includes("Used by"), "no Used by column");
  // Service-config discovery: the fixture cert (CN=svc-smoke, living outside
  // /etc/ssl) must be found via the fake nginx/caddy configs and carry both
  // service labels in the Used-by cell.
  const svcRow = [...d.querySelectorAll("table.tbl tr")].find((tr) => tr.textContent.includes("CN = svc-smoke"));
  check("observe certs: service-config cert discovered", !!svcRow, "svc-smoke cert row missing (service-config discovery broken)");
  check("observe certs: nginx label", !!svcRow && svcRow.textContent.includes("nginx"), "nginx label missing in Used by");
  check("observe certs: caddy label", !!svcRow && svcRow.textContent.includes("caddy"), "caddy label missing in Used by");
  await visit("#/obs-configs", 1600);
  check("observe configs renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Configs"));
  // The fake haproxy fails validation: the card must show an invalid badge
  // AND the validator's own explanation, not a bare red badge.
  check("observe configs: invalid haproxy flagged", [...d.querySelectorAll(".badge")].some((b) => b.textContent.trim() === "invalid"), "no invalid badge");
  check("observe configs: validator error shown", d.body.textContent.includes("cannot open certificate file"), "config_error not surfaced");
  await visit("#/obs-alerts");
  check("observe alerts: live card (engine wired)", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Alerts") && d.body.textContent.includes("Firing now:"), "alerts card missing");
  // Honest state: the empty-state text is shown iff there are no alerts. The
  // smoke's real security scan (Updates section) can find real CVEs and fire
  // security_updates, so "No alerts" is not guaranteed — assert the rendered
  // DOM matches the app's own alert list instead of a guaranteed empty state.
  const nAlerts = (w.__partout && w.__partout.alerts || []).length;
  if (nAlerts === 0) {
    check("observe alerts: empty state honest", d.body.textContent.includes("No alerts"), "no empty-state text");
  } else {
    check("observe alerts: alert rows shown when present", !!d.querySelector("section table.tbl") && !d.body.textContent.includes("No alerts (firing"), "expected alert rows, got empty state");
  }
  check("observe alerts: rules card", d.body.textContent.includes("Rules"), "rules card missing");
  check("observe alerts: seeded rule row", rowsWithText(d, "web restart loop") > 0, "rule row missing");
  check("observe alerts: M6.1 kind chip", rowsWithText(d, "service_restarting") > 0, "kind missing");
  check("observe alerts: new rule button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("New rule")), "no New rule button");
  const newRuleBtn = [...d.querySelectorAll("button")].find((b) => b.textContent.includes("New rule"));
  if (newRuleBtn) newRuleBtn.click();
  await sleep(300);
  check("observe alerts: rule form opens (kind select)",
    [...d.querySelectorAll("select option")].some((o) => o.value === "service_restarting"), "form kind select missing");
  check("observe alerts: drift kind option", [...d.querySelectorAll("select option")].some((o) => o.value === "config_drift"), "no config_drift option");

  await visit("#/account");
  check("account renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Account"));
  check("account: change-password form", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Update")) && d.querySelectorAll('input[type="password"]').length >= 2, "no password form");

  // --- Loading banner: while a page's data is loading AND empty, show
  //     "Loading…" and suppress the empty state (not "No jobs.") ---
  if (w.__partout) {
    const inst = w.__partout;
    await visit("#/jobs");
    const savedJobs = inst.jobs;
    inst.jobs = [];
    inst.pageLoading = true;
    await sleep(150);
    check("loading: banner while loading", d.body.textContent.includes("Loading…"), "no loading banner");
    check("loading: empty state suppressed during load", !d.body.textContent.includes("No jobs."), "empty state shown during load");
    inst.pageLoading = false;
    await sleep(150);
    check("loading: empty state shown after load", d.body.textContent.includes("No jobs."), "empty state not shown after load");
    check("empty: jobs has actionable CTA", [...d.querySelectorAll(".empty button")].some((b) => b.textContent.includes("New job")), "no 'New job' CTA in empty state");
    inst.jobs = savedJobs;
  }

  // --- Confirm dialog (replaces native confirm()) ---
  // Drive askConfirm directly so no real destructive action fires.
  if (w.__partout) {
    const inst = w.__partout;
    inst.askConfirm({ title: "Remove host", body: "Deletes all data.", mono: "web01 (ag_x)", confirmLabel: "Remove host", variant: "danger", requireText: "ag_x" });
    await sleep(150);
    check("confirm: dialog renders", !!d.querySelector(".overlay .dialog") && d.body.textContent.includes("Remove host"), "no confirm dialog");
    check("confirm: mono target shown", d.body.textContent.includes("web01 (ag_x)"), "mono target missing");
    check("confirm: type-to-confirm input", !!d.querySelector(".overlay input[placeholder='ag_x']"), "no type-to-confirm input");
    const cbtn = [...d.querySelectorAll(".overlay button")].find((b) => b.textContent.trim() === "Remove host");
    check("confirm: guard disables confirm", !!cbtn && cbtn.disabled, "confirm not disabled before type-to-confirm");
    inst.confirmBox.value = "wrong"; await sleep(100);
    check("confirm: wrong text keeps disabled", cbtn.disabled, "confirm enabled with wrong text");
    inst.confirmBox.value = "ag_x"; await sleep(100);
    check("confirm: right text enables", !cbtn.disabled, "confirm still disabled with right text");
    inst.confirmBoxNo(); await sleep(100); // cancel — never confirm (would delete a real host)
    check("confirm: cancel closes", !inst.confirmBox.open, "dialog not closed on cancel");
  }

  // --- Session expiry: toast + route preservation + return on re-login ---
  if (w.__partout) {
    const inst = w.__partout;
    const savedTok = inst.token;
    await visit("#/audit", 400);
    // The real 401 path: an invalidated token (server restart, 12h expiry)
    // must trigger the expiry flow through api(), not just the helper.
    inst.token = "bogus-token";
    try { await inst.api("/alerts"); } catch (e) { /* 401 throws */ }
    await sleep(250);
    check("session: real 401 triggers expiry", !inst.token, "token not cleared on 401");
    check("session: expired toast shown", [...d.querySelectorAll(".toast")].some((x) => x.textContent.includes("Session expired")), "no expired toast");
    check("session: signed out", !d.querySelector(".shell"), "still logged in after expiry");
    check("session: return route recorded", inst._returnRoute === "audit", "_returnRoute=" + JSON.stringify(inst._returnRoute));
    inst.token = savedTok; // re-login (the login form path calls afterLogin)
    await inst.afterLogin();
    await sleep(500);
    check("session: returned to previous page", (w.location.hash || "").includes("audit"), "hash=" + w.location.hash);
    check("session: shell restored", !!d.querySelector(".shell"), "shell missing after re-login");
    check("session: return route cleared after use", inst._returnRoute === "", "_returnRoute not cleared");
    // Explicit sign-out must NOT keep a return route (different intent).
    await visit("#/audit", 300);
    inst.signOut(); await sleep(200);
    check("session: explicit sign-out keeps no return route", inst._returnRoute === "", "explicit sign-out kept _returnRoute");
    inst.token = savedTok; await inst.afterLogin(); await sleep(400); // restore for later checks
  }

  // --- Login page: first-run password hint (render the logged-out view) ---
  if (w.__partout) {
    const savedToken = w.__partout.token;
    const savedProto = w.__partout.locProtocol, savedHost = w.__partout.locHostname;
    w.__partout.token = ""; // loggedIn is computed from token -> login page renders
    await sleep(300);
    check("login: first-run password hint", d.body.textContent.includes("First run?") && d.body.textContent.includes("admin_password.txt"), "login hint missing");
    // Cleartext warning: the smoke server is loopback http, so no banner must
    // show by default; a non-loopback http origin must show it; https never.
    check("login: no cleartext warning on loopback", !d.querySelector(".login-card .warn-box"), "warn-box rendered on loopback http");
    w.__partout.locHostname = "192.168.1.20"; await sleep(150);
    check("login: cleartext warning on non-loopback http", !!d.querySelector(".login-card .warn-box") && d.body.textContent.includes("not encrypted"), "no warn-box on exposed http");
    w.__partout.locProtocol = "https:"; w.__partout.locHostname = "192.168.1.20"; await sleep(150);
    check("login: no cleartext warning on https", !d.querySelector(".login-card .warn-box"), "warn-box rendered on https");
    w.__partout.locProtocol = savedProto; w.__partout.locHostname = savedHost;
    // The loopback predicate itself (shared with the computed) — all spellings.
    const lo = w.__partout.isLoopbackHost;
    check("login: isLoopbackHost matrix",
      lo("") === true && lo("localhost") === true && lo("LOCALHOST") === true && lo("app.localhost") === true &&
      lo("127.0.0.1") === true && lo("::1") === true && lo("[::1]") === true &&
      lo("192.168.1.20") === false && lo("example.com") === false && lo("203.0.113.7") === false,
      "isLoopbackHost matrix failed");
    w.__partout.token = savedToken; // restore -> shell renders again
    await sleep(400);
    check("login: restored to shell", !!d.querySelector(".shell"), "shell not restored after re-login");
  }

  console.log(failures.length ? "\n" + failures.length + " FAILURE(S)" : "\nALL UI DATA-RENDER CHECKS PASSED");
  w.close();
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => { console.error("harness error:", e); process.exit(2); });
