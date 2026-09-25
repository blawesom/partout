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

  await visit("#/fleet");
  check("fleet: host row", rowsWithText(d, "ag_") > 0);
  check("fleet: group scope rendered", !!d.querySelector(".nav-scope"));

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

  await visit("#/jobs");
  check("jobs: job name", rowsWithText(d, "nightly df") > 0, "no job row");
  check("jobs: task column", rowsWithText(d, "task_task_") > 0, "task column empty");

  await visit("#/tasks");
  check("tasks: name", rowsWithText(d, "check disk") > 0, "task name missing");
  check("tasks: description", rowsWithText(d, "df -h") > 0, "task description missing");
  check("tasks: playbooks card", d.body.textContent.includes("Playbooks"));

  await visit("#/updates", 1800);
  check("updates renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Updates"));

  await visit("#/secrets");
  check("secrets: row rendered", rowsWithText(d, "dbpass") > 0, "secret not rendered");

  await visit("#/policies");
  check("policies: name", rowsWithText(d, "deny-rm") > 0, "policy name missing");
  check("policies: match chip", rowsWithText(d, "command_regex") > 0, "match not rendered");

  await visit("#/users");
  check("users: admin + alice", rowsWithText(d, "admin") > 0 && rowsWithText(d, "alice") > 0, "users missing");

  await visit("#/obs-services", 1600);
  check("observe services: real unit",
    [...d.querySelectorAll("table.tbl tr")].some((tr) => /\.service|acme-serve|ssh|snap/.test(tr.textContent)),
    "no service rows");
  await visit("#/obs-certs", 1600);
  check("observe certs: real cert",
    [...d.querySelectorAll("table.tbl tr")].some((tr) => tr.textContent.includes("CN =")), "no cert rows");
  await visit("#/obs-configs", 1600);
  check("observe configs renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Configs"));
  await visit("#/obs-alerts");
  check("observe alerts: M6 placeholder", !!d.querySelector(".notavail") && d.querySelector(".notavail").textContent.includes("M6"));

  await visit("#/account");
  check("account renders", !!d.querySelector("h1") && d.querySelector("h1").textContent.includes("Account"));

  console.log(failures.length ? "\n" + failures.length + " FAILURE(S)" : "\nALL UI DATA-RENDER CHECKS PASSED");
  w.close();
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => { console.error("harness error:", e); process.exit(2); });
