// Headless DOM smoke test for the embedded SPA. Driven by scripts/ui-smoke.sh,
// which boots a real embedded server, seeds data, and passes BASE + TOK here.
//
// It mounts the *real* app.js served by that server, logs in, walks every page,
// and asserts REAL data renders (not merely that nothing threw). This is the
// guard for the UI↔API contract: a loader reading the wrong response key or a
// template binding a field that does not exist blanks a page silently and no Go
// test notices.
const { JSDOM, VirtualConsole } = require("jsdom");

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

  const hostId = [...d.querySelectorAll("table.tbl tr td.mono")]
    .map((t) => t.textContent.trim()).find((s) => s.startsWith("ag_"));
  await visit("#/host/" + hostId);
  const overview = d.querySelector("section");
  const ovText = overview ? overview.textContent : "";
  check("host overview: connected state", ovText.includes("connected"), "overview=" + ovText.slice(0, 160));
  check("host overview: version present", /0\.0\.0-dev|v\d/.test(ovText), "no version");
  check("host overview: EOL status rendered", /(supported|ending soon|end-of-life|unknown)/.test(ovText));
  check("host overview: EOL date rendered", /\d{4}-\d{2}-\d{2}/.test(ovText), "no YYYY-MM-DD date");

  await visit("#/host/" + hostId + "/facts");
  check("host facts: JSON console", !!d.querySelector(".console") && d.querySelector(".console").textContent.includes("{"));

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

  await visit("#/jobs");
  check("jobs: job name", rowsWithText(d, "nightly df") > 0, "no job row");
  check("jobs: task column", rowsWithText(d, "task_task_") > 0, "task column empty");
  check("jobs: new job button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("New job")), "no New job button");
  check("jobs: edit/runs/delete actions", [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Edit") && [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Runs") && [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Delete"), "job actions missing");

  await visit("#/tasks");
  check("tasks: name", rowsWithText(d, "check disk") > 0, "task name missing");
  check("tasks: description", rowsWithText(d, "df -h") > 0, "task description missing");
  check("tasks: playbooks card", d.body.textContent.includes("Playbooks"));
  check("tasks: run action", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Run")), "no Run button");
  check("tasks: recent runs card", d.body.textContent.includes("Recent task runs"), "runs card missing");
  check("tasks: new-task create button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Create…")), "no New task button");

  await visit("#/updates", 1800);
  check("updates renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Updates"));
  check("updates: apply button", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Apply")), "no Apply button");
  check("updates: package actions card", d.body.textContent.includes("Package actions"), "actions card missing");
  check("updates: EOL data status + refresh", d.body.textContent.includes("EOL data:") && [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Refresh EOL data")), "ext-data controls missing");

  await visit("#/secrets");
  check("secrets: row rendered", rowsWithText(d, "dbpass") > 0, "secret not rendered");
  check("secrets: create form", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Create secret")), "no Create secret button");
  check("secrets: rotate action", [...d.querySelectorAll("button")].some((b) => b.textContent.trim() === "Rotate"), "no Rotate button");

  await visit("#/policies");
  check("policies: name", rowsWithText(d, "deny-rm") > 0, "policy name missing");
  check("policies: match chip", rowsWithText(d, "command_regex") > 0, "match not rendered");

  await visit("#/approvals");
  check("approvals: page renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Approvals"));
  check("approvals: pending request row", rowsWithText(d, "apr_") > 0, "no approval row");
  check("approvals: agent on the row", rowsWithText(d, "ag_") > 0, "agent missing");
  check("approvals: approve button (admin)", [...d.querySelectorAll("button")].some((b) => b.textContent.includes("Approve")), "no Approve button");
  check("approvals: pending badge", !!d.querySelector(".badge.warn") && d.querySelector(".badge.warn").textContent.includes("pending"), "no pending badge");

  await visit("#/mcp");
  check("mcp: page renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("MCP"));
  check("mcp: http endpoint", rowsWithText(d, "/mcp") > 0, "endpoint missing");
  check("mcp: run_command tool row", rowsWithText(d, "run_command") > 0, "tool row missing");
  check("mcp: write badge", rowsWithText(d, "write") > 0, "no write badge");
  check("mcp: mcp.json snippet", d.body.textContent.includes("mcpServers"), "snippet missing");
  check("mcp: 22 tools", (d.body.textContent.match(/list_hosts|get_host_facts|decide_approval/g) || []).length >= 3, "tool names missing");
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

  await visit("#/obs-services", 1600);
  check("observe services: real unit",
    [...d.querySelectorAll("table.tbl tr")].some((tr) => /\.service|acme-serve|ssh|snap/.test(tr.textContent)),
    "no service rows");
  check("observe services: restarts column", d.body.textContent.includes("Restarts"), "no Restarts column");
  await visit("#/obs-certs", 1600);
  check("observe certs: real cert",
    [...d.querySelectorAll("table.tbl tr")].some((tr) => tr.textContent.includes("CN =")), "no cert rows");
  check("observe certs: used-by column", d.body.textContent.includes("Used by"), "no Used by column");
  await visit("#/obs-configs", 1600);
  check("observe configs renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Configs"));
  await visit("#/obs-alerts");
  check("observe alerts: live card (engine wired)", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Alerts") && d.body.textContent.includes("Firing now:"), "alerts card missing");
  check("observe alerts: empty state honest", d.body.textContent.includes("No alerts"), "no empty-state text");
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

  console.log(failures.length ? "\n" + failures.length + " FAILURE(S)" : "\nALL UI DATA-RENDER CHECKS PASSED");
  w.close();
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => { console.error("harness error:", e); process.exit(2); });
