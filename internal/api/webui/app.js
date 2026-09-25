/* Partout Fleet Management — web UI (buildless Vue 3 SPA, single component).
 *
 * One origin, no build step, no router/pinia dependencies. Talks to the
 * same-host REST + SSE API. Liveness is SSE-driven (ui-guidelines §10): a
 * single EventSource subscription; pages reconcile on state events. There is
 * no data polling. Disabled/not-in-build controls are data-driven off the
 * /capabilities probe (ui-guidelines §4).
 */
(function () {
  const { createApp } = Vue;
  const LS_TOKEN = "partout_token";

  // ---------------- formatting + state vocab (exposed to template) --------
  function fmtAgo(ts) {
    if (!ts) return "—";
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 5) return "just now";
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }
  function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleString() : "—"; }
  function fmtBytes(n) {
    if (!n) return "—";
    const u = ["B", "K", "M", "G", "T"]; let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(n >= 10 || i === 0 ? 0 : 1) + " " + u[i];
  }
  function agentBadge(s) { return ({ connected: { cls: "ok", label: "connected" }, disconnected: { cls: "bad", label: "disconnected" }, pending: { cls: "info", label: "pending" } })[s] || { cls: "neutral", label: s || "unknown" }; }
  function execBadge(s) { return ({ pending: "neutral", running: "info", succeeded: "ok", failed: "bad", partial: "warn", cancelled: "neutral" })[s] || "neutral"; }
  function runBadge(s) { return ({ queued: "neutral", delivered: "neutral", running: "info", succeeded: "ok", failed: "bad", timed_out: "warn", cancelled: "neutral", interrupted: "neutral", not_delivered: "outline-warn", denied: "outline-bad" })[s] || "neutral"; }
  function certBadge(c) {
    if (!c.not_after) return { cls: "neutral", label: "unknown" };
    if (c.days_remaining < 0) return { cls: "bad", label: "expired" };
    if (c.days_remaining < 7) return { cls: "bad", label: c.days_remaining + "d" };
    if (c.days_remaining < 30) return { cls: "warn", label: c.days_remaining + "d" };
    return { cls: "ok", label: c.days_remaining + "d" };
  }
  function svcBadge(u) {
    if (u.state === "failed") return { cls: "bad", label: "failed" };
    if (u.state === "active") return { cls: "ok", label: u.sub_state || "active" };
    if (["activating", "deactivating", "reloading"].includes(u.state)) return { cls: "info", label: u.state };
    return { cls: "neutral", label: u.state || "inactive" };
  }
  // EOL state vocabulary: supported|ending_soon|ended|unknown (server EOLState).
  function eolBadge(e) {
    const m = { ended: { cls: "bad", label: "end-of-life" }, ending_soon: { cls: "warn", label: "ending soon" }, supported: { cls: "ok", label: "supported" }, unknown: { cls: "neutral", label: "unknown" } };
    return m[e && e.state] || { cls: "neutral", label: (e && e.state) || "unknown" };
  }
  function buildQ(params) {
    const q = Object.entries(params).filter(([, v]) => v !== "" && v != null).map(([k, v]) => k + "=" + encodeURIComponent(v)).join("&");
    return q ? "?" + q : "";
  }
  function joinPath(a, b) { if (!a || a === "/") return "/" + b; if (a.endsWith("/")) return a + b; return a + "/" + b; }
  function parentPath(p) { const s = (p || "/").replace(/\/+$/, ""); const i = s.lastIndexOf("/"); return i <= 0 ? "/" : s.slice(0, i); }
  function obj(v) { try { return v ? JSON.parse(v) : null; } catch (e) { return v; } }

  class ApiError extends Error { constructor(status, message, code, data) { super(message); this.status = status; this.code = code; this.data = data; } }

  const TEMPLATE = `
  <!-- ============ LOGIN ============ -->
  <div v-if="!loggedIn" class="login-wrap">
    <div class="login-card">
      <div class="brand" style="padding:0 0 16px">
        <div class="logo">P</div>
        <div><div class="word">Partout</div><div class="sub">Fleet Management</div></div>
      </div>
      <form @submit.prevent="doLogin">
        <label class="fld"><span>Username</span><input v-model="loginForm.username" autocomplete="username" autofocus /></label>
        <label class="fld"><span>Password</span><input v-model="loginForm.password" type="password" autocomplete="current-password" /></label>
        <div v-if="loginErr" class="err-box" style="margin-bottom:12px">{{ loginErr }}</div>
        <button class="btn primary" style="width:100%;justify-content:center" :disabled="loginBusy">
          <span v-if="loginBusy" class="spin"></span> Sign in
        </button>
      </form>
    </div>
  </div>
  <!-- ============ SHELL ============ -->
  <div v-else class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="logo">P</div>
        <div><div class="word">Partout</div><div class="sub">Fleet Management</div></div>
        <div class="port">:{{ port }}</div>
      </div>
      <nav class="nav">
        <div class="nav-section">Fleet</div>
        <div v-for="n in fleetNav()" :key="n.key"
             :class="['nav-item', {active: page===n.key, disabled: !navEnabled(n)}]"
             :title="navTitle(n)" @click="navClick(n)">
          <span class="icon">{{ n.icon }}</span>{{ n.label }}
          <span v-if="!navEnabled(n)" class="chip-ms">{{ navTag(n) }}</span>
        </div>

        <div class="nav-section">Observe</div>
        <div v-for="n in obsNav()" :key="n.key"
             :class="['nav-item', {active: page===n.key, disabled: !!n.placeholder || !capOn('observe')}]"
             :title="n.placeholder ? ('Not yet available — ' + n.placeholder) : ''"
             @click="!n.placeholder && capOn('observe') && go(n.key)">
          <span class="icon">{{ n.icon }}</span>{{ n.label }}
          <span v-if="n.placeholder" class="chip-ms">{{ n.placeholder }}</span>
        </div>

        <div v-if="groups.length" class="nav-section">Groups</div>
        <div v-for="g in groups" :key="g.name" class="nav-scope" :class="{active: scope===g.name}" @click="setScope(g.name)">
          <span class="mono">#{{ g.name }}</span>
        </div>
      </nav>

      <div class="usercard" @click="userMenu=!userMenu">
        <div class="avatar">{{ initials }}</div>
        <div class="who">
          <div class="uname">{{ (me && me.username) || '—' }}</div>
          <div class="urole"><span class="badge neutral" style="font-size:10px">{{ (me && me.role) || '—' }}</span></div>
        </div>
      </div>
    </aside>

    <div class="main">
      <div class="topbar">
        <div class="crumbs">
          <span @click="go('fleet')" style="cursor:pointer">Fleet</span>
          <template v-if="crumbHost"><span class="sep">›</span><span class="cur">{{ crumbHost }}</span></template>
          <template v-if="crumbPage"><span class="sep">›</span><span class="cur">{{ crumbPage }}</span></template>
        </div>
        <div class="spacer"></div>
        <div class="sse-dot" :title="'stream: /api/v1/events — ' + sseStatus">
          <span class="dot" :class="sseDot"></span>{{ sseStatus }}
        </div>
      </div>

      <div class="body">
        <div v-if="userMenu" @click="userMenu=false" style="position:fixed;inset:0;z-index:40;background:rgba(15,23,42,.25)">
          <div style="position:absolute;bottom:70px;left:12px;background:#fff;border:1px solid var(--border);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);padding:6px;min-width:180px">
            <div class="nav-item" @click.stop="userMenu=false; go('account')">Account</div>
            <div class="nav-item" @click.stop="signOut">Sign out</div>
          </div>
        </div>

        <!-- ============ FLEET ============ -->
        <section v-if="page==='fleet'">
          <h1 class="page">Fleet Management</h1>
          <p class="page-sub">{{ scopedHosts.length }} host{{ scopedHosts.length===1?'':'s' }}<template v-if="scope"> · scoped to <b>#{{ scope }}</b></template></p>
          <div class="grid cols-3" style="margin-bottom:16px">
            <div class="stat ok"><div class="lbl">🛡 Connected</div><div class="num">{{ health.connected }}</div></div>
            <div class="stat bad"><div class="lbl">✕ Disconnected</div><div class="num">{{ health.disconnected }}</div></div>
            <div class="stat info"><div class="lbl">◷ Pending</div><div class="num">{{ health.pending }}</div></div>
          </div>
          <div class="card">
            <div class="head"><h2>Hosts</h2><div class="spacer"></div>
              <button class="btn sm" @click="createGroup" :disabled="!isOperator">+ Group</button>
            </div>
            <table class="tbl">
              <thead><tr><th>Host</th><th>State</th><th>Version</th><th>Last seen</th></tr></thead>
              <tbody>
                <tr v-for="h in scopedHosts" :key="h.id" class="click" @click="go('host/'+h.id)">
                  <td class="mono">{{ h.id }}</td>
                  <td><span class="badge" :class="agentBadge(h.state).cls">{{ agentBadge(h.state).label }}</span></td>
                  <td class="mono">{{ h.version || '—' }}</td>
                  <td class="muted">{{ fmtAgo(h.last_seen) }}</td>
                </tr>
                <tr v-if="!hostsLoading && !scopedHosts.length"><td colspan="4"><div class="empty"><div class="big">▦</div>No hosts enrolled yet.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ HOST DETAIL ============ -->
        <section v-else-if="page==='host'">
          <div class="tabs">
            <div class="tab" :class="{active: p2==='overview' || !p2}" @click="go('host/'+p1)">Overview</div>
            <div class="tab" :class="{active: p2==='facts'}" @click="go('host/'+p1+'/facts')">Facts</div>
          </div>
          <template v-if="p2!=='facts'">
            <div class="grid cols-2">
              <div class="card">
                <h2>{{ p1 }}</h2>
                <p class="cap">Host overview</p>
                <dl class="kv">
                  <dt>State</dt><dd><span class="badge" :class="agentBadge((host && host.state) || 'disconnected').cls">{{ agentBadge((host && host.state) || 'disconnected').label }}</span></dd>
                  <dt>UUID</dt><dd class="mono">{{ (host && host.uuid) || '—' }}</dd>
                  <dt>Version</dt><dd class="mono">{{ (host && host.version) || '—' }}</dd>
                  <dt>First seen</dt><dd>{{ host ? fmtDate(host.first_seen) : '—' }}</dd>
                  <dt>Last seen</dt><dd>{{ host ? fmtAgo(host.last_seen) : '—' }}</dd>
                  <dt v-if="host && host.roles && host.roles.length">Roles</dt>
                  <dd v-if="host && host.roles && host.roles.length"><span class="chip" v-for="r in host.roles" :key="r">{{ r }}</span></dd>
                </dl>
              </div>
              <div class="card">
                <h2>OS end-of-support</h2>
                <p class="cap">Live from endoflife.date (external data)</p>
                <template v-if="hostEol && hostEol.distro">
                  <dl class="kv">
                    <dt>Distro</dt><dd>{{ hostEol.distro }} <span class="mono muted">{{ hostEol.cycle }}</span></dd>
                    <dt>Status</dt><dd><span class="badge" :class="eolBadge(hostEol).cls">{{ eolBadge(hostEol).label }}</span></dd>
                    <dt>EOL date</dt><dd>{{ hostEol.eol_date || '—' }}</dd>
                    <dt v-if="hostEol.extended_support">Extended support</dt>
                    <dd v-if="hostEol.extended_support">{{ hostEol.extended_support }}</dd>
                    <dt>Feed age</dt><dd class="muted">{{ hostEol.cache_age_days }}d</dd>
                  </dl>
                </template>
                <p v-else class="muted">No EOL data (external data not wired or distro unknown).</p>
              </div>
            </div>
          </template>
          <div v-else class="card">
            <h2>Host facts</h2><p class="cap">Scalar facts uploaded by the agent</p>
            <div v-if="hostFacts && hostFacts.facts" class="console" style="max-height:520px">{{ JSON.stringify(hostFacts.facts, null, 2) }}</div>
            <p v-else class="muted">No facts recorded for this host.</p>
          </div>
        </section>

        <!-- ============ EXECUTE ============ -->
        <section v-else-if="page==='execute'">
          <h1 class="page">Execute</h1>
          <p class="page-sub">Run a command across a selector. Resolution is server-authoritative.</p>
          <div class="card">
            <div class="toolbar">
              <label class="fld" style="flex:0 0 260px;margin:0"><span>Selector</span>
                <input v-model="exSel" class="mono" placeholder="all · host:ag_x · group:db" @keyup.enter="previewSelector" /></label>
              <button class="btn sm" @click="previewSelector" :disabled="previewLoading || !exSel">
                <span v-if="previewLoading" class="spin"></span> Resolve
              </button>
              <span class="muted small" v-if="preview && !preview.error">{{ preview.count }} host(s) match</span>
              <span class="err-box" style="margin:0" v-if="preview && preview.error">{{ preview.error }}</span>
            </div>
            <div class="grid cols-2">
              <label class="fld"><span>Command</span><input v-model="exCmd" class="mono" placeholder="whoami" /></label>
              <label class="fld"><span>Timeout (s)</span><input type="number" v-model.number="exTimeout" min="1" /></label>
            </div>
            <label class="fld"><span>Args (space-separated)</span><input v-model="exArgs" class="mono" placeholder="-a -l" /></label>
            <div v-if="!isOperator" class="warn-box">Requires operator role to dispatch.</div>
            <button class="btn primary" :disabled="!isOperator || !exCmd || !exSel" @click="dispatch">Run command</button>
          </div>

          <div class="card">
            <div class="head"><h2>Recent executions</h2></div>
            <table class="tbl">
              <thead><tr><th>ID</th><th>Command</th><th>Selector</th><th>State</th><th>When</th></tr></thead>
              <tbody>
                <tr v-for="e in executions" :key="e.id" class="click" @click="go('exec/'+e.id)">
                  <td class="mono">{{ e.id }}</td>
                  <td class="mono">{{ e.cmd }}<template v-if="e.args && e.args.length"> {{ e.args.join(' ') }}</template></td>
                  <td class="mono">{{ e.selector }}</td>
                  <td><span class="badge" :class="execBadge(e.state)">{{ e.state }}</span></td>
                  <td class="muted">{{ fmtAgo(e.created) }}</td>
                </tr>
                <tr v-if="!executions.length"><td colspan="5"><div class="empty">No executions yet.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ EXEC DETAIL ============ -->
        <section v-else-if="page==='exec'">
          <h1 class="page">Execution <span class="mono muted">{{ p1 }}</span></h1>
          <div class="card" v-if="execDetail">
            <div class="toolbar">
              <span class="badge" :class="execBadge(execDetail.state)">{{ execDetail.state }}</span>
              <span class="muted mono">{{ execDetail.cmd }}<template v-if="execDetail.args"> {{ execDetail.args.join(' ') }}</template></span>
              <span class="muted small">selector: {{ execDetail.selector }}</span>
              <div class="spacer"></div>
              <button v-if="['running','pending'].includes(execDetail.state) && isOperator" class="btn danger sm" @click="cancelExec(execDetail.id)">Cancel</button>
            </div>
            <table class="tbl">
              <thead><tr><th>Host</th><th>State</th><th>Exit</th><th>Duration</th><th>Output</th></tr></thead>
              <tbody>
                <tr v-for="r in (execDetail.runs||[])" :key="r.run_id">
                  <td class="mono">{{ r.agent_id }}</td>
                  <td><span class="badge" :class="runBadge(r.state)">{{ r.state }}</span></td>
                  <td class="mono">{{ r.state==='succeeded' ? (r.exit_code||0) : '—' }}</td>
                  <td class="mono">{{ r.duration_ms ? (r.duration_ms/1000).toFixed(2)+'s' : '—' }}</td>
                  <td>
                    <div class="console" style="max-width:520px;max-height:180px">
                      <template v-for="o in outFor(r.run_id)" :key="o.run_id">
                        <div v-if="o.stdout">{{ o.stdout }}</div>
                        <div v-if="o.stderr" class="line-err">{{ o.stderr }}</div>
                      </template>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="card" v-else><p class="muted">Loading…</p></div>
        </section>

        <!-- ============ AUDIT ============ -->
        <section v-else-if="page==='audit'">
          <h1 class="page">Audit Log</h1>
          <p class="page-sub">Read-only event history (PRD R9).</p>
          <div class="toolbar">
            <select v-model="auditKind" style="max-width:220px" @change="loadAudit">
              <option value="">All kinds</option>
              <option v-for="k in auditKinds" :key="k" :value="k">{{ k }}</option>
            </select>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>When</th><th>Kind</th><th>Actor</th><th>Agent</th><th>Detail</th></tr></thead>
              <tbody>
                <tr v-for="(a,i) in audit" :key="i">
                  <td class="muted">{{ fmtDate(a.ts) }}</td>
                  <td><span class="chip brand">{{ a.kind }}</span></td>
                  <td class="mono">{{ a.actor || '—' }}</td>
                  <td class="mono">{{ a.agent_id || '—' }}</td>
                  <td class="mono small" style="max-width:420px;overflow:hidden;text-overflow:ellipsis">{{ typeof a.payload==='string'? a.payload : (a.payload && a.payload.message) || JSON.stringify(a.payload||{}) }}</td>
                </tr>
                <tr v-if="!audit.length"><td colspan="5"><div class="empty">No audit events.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ SESSIONS ============ -->
        <section v-else-if="page==='sessions'">
          <h1 class="page">Sessions</h1>
          <p class="page-sub">PTY terminal sessions and recordings (M2).</p>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>ID</th><th>Host</th><th>Command</th><th>State</th><th></th></tr></thead>
              <tbody>
                <tr v-for="s in sessions" :key="s.id || s.session_id">
                  <td class="mono">{{ s.id || s.session_id }}</td>
                  <td class="mono">{{ s.agent_id || s.host_id }}</td>
                  <td class="mono">{{ (s.cmd || (s.args && s.args.join(' '))) || 'shell' }}</td>
                  <td><span class="badge neutral">{{ s.state || '—' }}</span></td>
                  <td><button class="btn sm" @click="go('session/'+(s.id||s.session_id))">Replay</button></td>
                </tr>
                <tr v-if="!sessions.length"><td colspan="5"><div class="empty">No sessions.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ SESSION REPLAY ============ -->
        <section v-else-if="page==='session'">
          <h1 class="page">Session <span class="mono muted">{{ p1 }}</span></h1>
          <div class="card" v-if="sessionReplay">
            <div class="console">
              <div class="hd"><span class="lights"><i></i><i></i><i></i></span> stream: session/{{ p1 }} (replay)</div>
              {{ replayText() }}
            </div>
          </div>
          <div class="card" v-else><p class="muted">No replay data.</p></div>
        </section>

        <!-- ============ FILES ============ -->
        <section v-else-if="page==='files'">
          <h1 class="page">Files</h1>
          <p class="page-sub">Host file browser (M2).</p>
          <div class="toolbar">
            <select :value="fileHost" style="max-width:260px" @change="pickFileHost($event.target.value)">
              <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.id }}</option>
            </select>
            <input v-model="fileDir" class="mono" style="flex:1" @keyup.enter="listFiles" />
            <button class="btn sm" @click="fileUp">↑</button>
            <button class="btn sm" @click="listFiles">Open</button>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Name</th><th>Size</th><th>Mode</th><th>Modified</th></tr></thead>
              <tbody>
                <tr v-for="(f,i) in fileEntries" :key="i">
                  <td class="mono" :style="{cursor: f.is_dir?'pointer':'default'}" @click="openFile(f)">{{ f.is_dir ? '📁' : (f.is_symlink ? '🔗' : '📄') }} {{ f.name }}</td>
                  <td class="mono">{{ f.is_dir ? '—' : fmtBytes(f.size) }}</td>
                  <td class="mono">{{ f.mode || '—' }}</td>
                  <td class="muted">{{ fmtAgo(f.mtime_unix) }}</td>
                </tr>
                <tr v-if="!fileLoading && !fileEntries.length"><td colspan="4"><div class="empty">{{ fileHost ? 'Empty or no access.' : 'No hosts available.' }}</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ JOBS ============ -->
        <section v-else-if="page==='jobs'">
          <h1 class="page">Jobs</h1>
          <p class="page-sub">Scheduled jobs (M3).</p>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>ID</th><th>Name</th><th>Task</th><th>Schedule</th><th>Selector</th><th>Enabled</th><th></th></tr></thead>
              <tbody>
                <tr v-for="j in jobs" :key="j.id">
                  <td class="mono">{{ j.id }}</td>
                  <td>{{ j.name }}</td>
                  <td class="mono">{{ j.task_id }}<template v-if="j.task_version">@{{ j.task_version }}</template></td>
                  <td class="mono">{{ j.cron }}</td>
                  <td class="mono">{{ j.selector }}</td>
                  <td>{{ j.enabled ? 'yes' : 'no' }}</td>
                  <td><button class="btn sm" :disabled="!isOperator" @click="runJob(j)">Run now</button></td>
                </tr>
                <tr v-if="!jobs.length"><td colspan="7"><div class="empty">No jobs.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ TASKS ============ -->
        <section v-else-if="page==='tasks'">
          <h1 class="page">Tasks &amp; Playbooks</h1>
          <p class="page-sub">Multi-step automation (M3).</p>
          <div class="grid cols-2">
            <div class="card">
              <h2>Tasks</h2><p class="cap">Single-step units</p>
              <table class="tbl"><thead><tr><th>ID</th><th>Name</th><th>Description</th></tr></thead>
                <tbody>
                  <tr v-for="t in tasks" :key="t.id"><td class="mono">{{ t.id }}</td><td>{{ t.name }}</td><td class="muted">{{ t.description || '—' }}</td></tr>
                  <tr v-if="!tasks.length"><td colspan="3"><div class="empty">No tasks.</div></td></tr>
                </tbody>
              </table>
            </div>
            <div class="card">
              <h2>Playbooks</h2><p class="cap">Sequences of tasks</p>
              <table class="tbl"><thead><tr><th>ID</th><th>Name</th><th>Task</th><th>Selector</th></tr></thead>
                <tbody>
                  <tr v-for="p in playbooks" :key="p.id">
                    <td class="mono">{{ p.id }}</td><td>{{ p.name }}</td>
                    <td class="mono">{{ p.task_id }}<template v-if="p.task_version">@{{ p.task_version }}</template></td>
                    <td class="mono">{{ p.selector || '—' }}</td>
                  </tr>
                  <tr v-if="!playbooks.length"><td colspan="4"><div class="empty">No playbooks.</div></td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- ============ UPDATES ============ -->
        <section v-else-if="page==='updates'">
          <h1 class="page">Updates</h1>
          <p class="page-sub">Available package updates for the selected host (M3).</p>
          <div class="toolbar">
            <select :value="updHost" style="max-width:260px" @change="updHost=$event.target.value; loadUpdates()">
              <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.id }}</option>
            </select>
            <button class="btn sm" @click="loadUpdates">Refresh</button>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Package</th><th>Installed</th><th>Available</th><th>Vulns</th></tr></thead>
              <tbody>
                <tr v-for="(u,i) in updates" :key="u.name || i">
                  <td class="mono">{{ u.name }}</td>
                  <td class="mono">{{ u.installed || '—' }}</td>
                  <td class="mono">{{ u.available || '—' }}</td>
                  <td>
                    <span v-if="u.is_security" class="badge bad">security</span>
                    <span v-if="u.vuln_count" class="badge" :class="u.max_severity==='critical'?'bad':(u.max_severity==='high'?'warn':'neutral')">{{ u.vuln_count }} · {{ u.max_severity }}</span>
                    <span v-if="!u.is_security && !u.vuln_count" class="muted">—</span>
                  </td>
                </tr>
                <tr v-if="!updates.length"><td colspan="4"><div class="empty">No pending updates (or no host selected).</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ SECRETS ============ -->
        <section v-else-if="page==='secrets'">
          <h1 class="page">Secrets</h1>
          <p class="page-sub">Encrypted at rest; values are write-only and never displayed (ui-guidelines §12.6).</p>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Name</th><th>Selector</th><th></th></tr></thead>
              <tbody>
                <tr v-for="s in secrets" :key="s.name">
                  <td class="mono">{{ s.name }}</td>
                  <td class="mono">{{ s.selector || 'all' }}</td>
                  <td><button class="btn danger sm" :disabled="!isAdmin" @click="deleteSecret(s.name)">Delete</button></td>
                </tr>
                <tr v-if="!secrets.length"><td colspan="3"><div class="empty">No secrets (or feature disabled).</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ POLICIES ============ -->
        <section v-else-if="page==='policies'">
          <h1 class="page">Policies</h1>
          <p class="page-sub">Command policy rules (PRD R7).</p>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>ID</th><th>Name</th><th>Effect</th><th>Priority</th><th>Match</th><th></th></tr></thead>
              <tbody>
                <tr v-for="p in policies" :key="p.id">
                  <td class="mono">{{ p.id }}</td>
                  <td>{{ p.name }}</td>
                  <td><span class="badge" :class="p.effect==='deny'?'bad':(p.effect==='allow'?'ok':'neutral')">{{ p.effect }}</span></td>
                  <td class="mono">{{ p.priority }}</td>
                  <td><span class="chip" v-for="(v,k) in matchPairs(p)" :key="k">{{ k }}={{ v }}</span><span v-if="!matchPairs(p).length" class="muted">—</span></td>
                  <td><button class="btn danger sm" :disabled="!isAdmin" @click="deletePolicy(p.id)">Delete</button></td>
                </tr>
                <tr v-if="!policies.length"><td colspan="6"><div class="empty">No policies.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ PROVISION ============ -->
        <section v-else-if="page==='provision'">
          <h1 class="page">Provision</h1>
          <p class="page-sub">Server-initiated host onboarding (R17, admin).</p>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>ID</th><th>Host</th><th>Mode</th><th>State</th></tr></thead>
              <tbody>
                <tr v-for="r in provRuns" :key="r.id">
                  <td class="mono">{{ r.id }}</td><td class="mono">{{ r.host }}</td>
                  <td class="mono">{{ r.mode }}</td><td><span class="badge neutral">{{ r.state }}</span></td>
                </tr>
                <tr v-if="!provRuns.length"><td colspan="4"><div class="empty">No provision runs.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ USERS ============ -->
        <section v-else-if="page==='users'">
          <h1 class="page">Users</h1>
          <p class="page-sub">Local identity principals (admin).</p>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Username</th><th>Role</th><th></th></tr></thead>
              <tbody>
                <tr v-for="u in users" :key="u.username || u.name">
                  <td class="mono">{{ u.username || u.name }}</td>
                  <td><span class="badge neutral">{{ u.role }}</span></td>
                  <td><button class="btn danger sm" @click="deleteUser(u.username||u.name)">Delete</button></td>
                </tr>
                <tr v-if="!users.length"><td colspan="3"><div class="empty">No users.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ OBSERVE · SERVICES ============ -->
        <section v-else-if="page==='obs-services'">
          <h1 class="page">Services</h1>
          <p class="page-sub">Fleet service health from agent-collected facts (M5, R18).</p>
          <div class="toolbar">
            <input v-model="svcLabel" placeholder="filter by label" @keyup.enter="loadServices" style="max-width:200px" />
            <select v-model="svcState" @change="loadServices">
              <option value="">any state</option><option value="active">active</option>
              <option value="failed">failed</option><option value="inactive">inactive</option>
            </select>
            <button class="btn sm" @click="loadServices">Apply</button>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Unit</th><th>Host</th><th>State</th><th>Enabled</th><th>Restart</th><th>Memory</th><th>Labels</th></tr></thead>
              <tbody>
                <tr v-for="(row,i) in services" :key="i">
                  <td class="mono">{{ row.unit.name }}</td>
                  <td class="mono">{{ row.host_id }}</td>
                  <td><span class="badge" :class="svcBadge(row.unit).cls">{{ svcBadge(row.unit).label }}</span></td>
                  <td>{{ row.unit.enabled ? 'yes' : 'no' }}</td>
                  <td class="mono">{{ row.unit.restart_policy || '—' }}</td>
                  <td class="mono">{{ row.unit.memory_current ? fmtBytes(row.unit.memory_current) : '—' }}</td>
                  <td><span class="chip" v-for="l in (row.unit.labels||[])" :key="l">{{ l }}</span></td>
                </tr>
                <tr v-if="!services.length"><td colspan="7"><div class="empty">No service facts (agents must be connected &amp; systemd present).</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ OBSERVE · CERTIFICATES ============ -->
        <section v-else-if="page==='obs-certs'">
          <h1 class="page">Certificates</h1>
          <p class="page-sub">TLS certificate inventory (M5, R20).</p>
          <div class="toolbar">
            <label class="fld" style="margin:0;display:flex;align-items:center;gap:8px">
              <span style="margin:0">expires within</span>
              <input type="number" v-model="certDays" min="0" style="width:90px" @keyup.enter="loadCerts" placeholder="days" />
              <button class="btn sm" @click="loadCerts">Apply</button>
            </label>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Subject</th><th>Host</th><th>Expires</th><th>Chain</th><th>Key</th><th>Self-signed</th></tr></thead>
              <tbody>
                <tr v-for="(row,i) in certs" :key="i">
                  <td><div class="mono small">{{ row.cert.subject || row.cert.path }}</div></td>
                  <td class="mono">{{ row.host_id }}</td>
                  <td><span class="badge" :class="certBadge(row.cert).cls">{{ certBadge(row.cert).label }}</span></td>
                  <td><span class="badge" :class="!row.cert.chain_checked?'neutral':(row.cert.chain_valid?'ok':'bad')">{{ !row.cert.chain_checked?'unchecked':(row.cert.chain_valid?'valid':'broken') }}</span></td>
                  <td class="mono">{{ row.cert.key_type || '—' }}</td>
                  <td>{{ row.cert.self_signed ? 'yes' : 'no' }}</td>
                </tr>
                <tr v-if="!certs.length"><td colspan="6"><div class="empty">No certificate facts.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ OBSERVE · CONFIGS ============ -->
        <section v-else-if="page==='obs-configs'">
          <h1 class="page">Configs</h1>
          <p class="page-sub">HAProxy / Nginx validity &amp; topology (M5, R19).</p>
          <div class="toolbar">
            <select v-model="cfgKind" @change="loadConfigs">
              <option value="">any kind</option><option value="haproxy">haproxy</option><option value="nginx">nginx</option>
            </select>
            <button class="btn sm" @click="loadConfigs">Apply</button>
          </div>
          <div class="card" v-for="(c,i) in configs" :key="i">
            <div class="head">
              <h2>{{ c.kind }} <span class="muted mono small" v-if="c.haproxy || c.nginx">· {{ (c.haproxy||c.nginx).version }}</span></h2>
              <span class="badge" :class="((c.haproxy||c.nginx) && (c.haproxy||c.nginx).config_valid)?'ok':'bad'">{{ ((c.haproxy||c.nginx) && (c.haproxy||c.nginx).config_valid)?'valid':'invalid' }}</span>
              <div class="spacer"></div>
              <span class="muted mono small">{{ c.host_id }}</span>
            </div>
            <template v-if="c.haproxy">
              <p class="cap">{{ (c.haproxy.backends||[]).length }} backends · {{ (c.haproxy.listeners||[]).length }} listeners</p>
              <table class="tbl" v-if="(c.haproxy.backends||[]).length">
                <thead><tr><th>Backend</th><th>Servers</th></tr></thead>
                <tbody><tr v-for="b in c.haproxy.backends" :key="b.name"><td class="mono">{{ b.name }}</td><td class="mono">{{ b.servers || '—' }}</td></tr></tbody>
              </table>
            </template>
            <template v-if="c.nginx">
              <p class="cap">{{ (c.nginx.vhosts||[]).length }} vhosts</p>
              <table class="tbl" v-if="(c.nginx.vhosts||[]).length">
                <thead><tr><th>Server</th><th>Listen</th><th>TLS</th><th>Cert</th><th>Upstream</th></tr></thead>
                <tbody><tr v-for="v in c.nginx.vhosts" :key="v.server_name">
                  <td class="mono">{{ v.server_name }}</td><td class="mono">{{ v.port }}</td>
                  <td>{{ v.tls?'yes':'no' }}</td><td class="mono small">{{ v.tls_cert||'—' }}</td><td class="mono small">{{ v.upstream||'—' }}</td>
                </tr></tbody>
              </table>
            </template>
          </div>
          <div class="card" v-if="!configs.length"><div class="empty">No config facts (haproxy/nginx must be installed).</div></div>
        </section>

        <!-- ============ OBSERVE · ALERTS (M6 placeholder) ============ -->
        <section v-else-if="page==='obs-alerts'">
          <h1 class="page">Alerts</h1>
          <p class="page-sub">Threshold rules, firing/resolved state, SSE fan-out (R23, R25).</p>
          <div class="notavail">
            <span class="tag">M6 · not yet available</span>
            <h3>Alert engine not built</h3>
            <p>The observe <b>data path</b> (Services, Certificates, Configs) is live. The alert
            engine — rule store, periodic evaluation, firing/resolved states, and
            <span class="mono">alert.firing</span>/<span class="mono">alert.resolved</span> SSE fan-out —
            ships in <b>M6</b>. This page will render active alerts here.</p>
          </div>
        </section>

        <!-- ============ ACCOUNT ============ -->
        <section v-else-if="page==='account'">
          <h1 class="page">Account</h1>
          <p class="page-sub">Signed in as <b>{{ (me && me.username) }}</b> ({{ (me && me.role) }}).</p>
          <div class="card" style="max-width:420px">
            <h2>Change password</h2><p class="cap">Requires local-user auth to be enabled.</p>
            <template v-if="caps.auth">
              <label class="fld"><span>Current password</span><input type="password" v-model="pw.current" /></label>
              <label class="fld"><span>New password</span><input type="password" v-model="pw.next" /></label>
              <div v-if="pwMsg" class="info-box">{{ pwMsg }}</div>
              <div v-if="pwErr" class="err-box">{{ pwErr }}</div>
              <button class="btn primary" :disabled="!pw.current || !pw.next" @click="changePassword">Update</button>
            </template>
            <p v-else class="muted">Local-user auth is not enabled on this build (single-user mode).</p>
          </div>
        </section>

        <section v-else>
          <div class="notavail"><h3>Unknown page: {{ page }}</h3><p><a @click.prevent="go('fleet')" style="cursor:pointer">Back to fleet</a></p></div>
        </section>
      </div>
    </div>
  </div>
  `;

  const app = createApp({
    template: TEMPLATE,
    data() {
      return {
        token: localStorage.getItem(LS_TOKEN) || "",
        me: null, caps: {}, loginForm: { username: "", password: "" },
        loginErr: "", loginBusy: false, userMenu: false,
        route: (location.hash || "#/fleet").replace(/^#\/?/, ""),
        sseStatus: "disconnected",
        groups: [], scope: null,
        hosts: [], hostsLoading: false, host: null, hostFacts: null, hostEol: null,
        exSel: "all", exCmd: "", exArgs: "", exTimeout: 60,
        preview: null, previewLoading: false, executions: [],
        execDetail: null, execOutput: [],
        audit: [], auditKind: "",
        sessions: [], sessionReplay: null,
        fileHost: "", fileDir: "/", fileEntries: [], fileLoading: false,
        updHost: "", jobs: [], jobRuns: [], tasks: [], playbooks: [], updates: [],
        secrets: [], policies: [], provRuns: [], users: [],
        services: [], svcLabel: "", svcState: "",
        certs: [], certDays: "",
        configs: [], cfgKind: "",
        pw: { current: "", next: "" }, pwMsg: "", pwErr: "",
      };
    },
    computed: {
      loggedIn() { return !!this.token; },
      parts() { return this.route.split("/").filter(Boolean); },
      page() {
        const p = this.parts;
        if (p[0] === "host") return "host";
        if (p[0] === "exec") return "exec";
        if (p[0] === "session") return "session";
        if (p[0] === "obs") return "obs-" + (p[1] || "services");
        return p[0] || "fleet";
      },
      p1() { return this.parts[1] || ""; },
      p2() { return this.parts[2] || ""; },
      isOperator() { return ["operator", "admin"].includes(this.me?.role); },
      isAdmin() { return this.me?.role === "admin"; },
      initials() { return (this.me?.username || "?").slice(0, 2).toUpperCase(); },
      port() { return location.port || (location.protocol === "https:" ? "443" : "80"); },
      sseDot() { return this.sseStatus === "connected" ? "ok" : this.sseStatus === "reconnecting" ? "warn" : "down"; },
      crumbHost() { return this.page === "host" ? this.p1 : ""; },
      crumbPage() { if (this.page === "host") return this.p2 || "overview"; if (this.page === "exec") return "execution"; return ""; },
      health() {
        const c = { connected: 0, disconnected: 0, pending: 0 };
        for (const h of this.hosts) if (c[h.state] !== undefined) c[h.state]++;
        return c;
      },
      scopedHosts() {
        if (!this.scope) return this.hosts;
        const g = this.groups.find(g => g.name === this.scope);
        if (!g) return this.hosts;
        const sel = (g.selector || "").trim();
        if (sel === "all") return this.hosts;
        const m = sel.match(/^host:(.+)$/);
        if (m) return this.hosts.filter(h => h.id === m[1]);
        return this.hosts;
      },
      auditKinds() { return [...new Set(this.audit.map(a => a.kind))]; },
    },
    methods: {
      fmtAgo, fmtDate, fmtBytes, agentBadge, execBadge, runBadge, certBadge, svcBadge, eolBadge,
      async api(path, opts = {}) {
        const headers = { ...(opts.headers || {}) };
        if (this.token) headers["Authorization"] = "Bearer " + this.token;
        if (opts.body !== undefined && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
        const res = await fetch("/api/v1" + path, {
          method: opts.method || (opts.body !== undefined ? "POST" : "GET"),
          headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        });
        if (res.status === 401) { this.signOut(); throw new ApiError(401, "unauthorized"); }
        if (res.status === 503) { this.refreshCaps(); throw new ApiError(503, "disabled"); }
        let data = null; try { data = await res.json(); } catch (e) { }
        if (!res.ok) throw new ApiError(res.status, (data && data.message) || String(res.status), data && data.code, data);
        return data;
      },
      capOn(name) { return this.caps[name] === true; },
      // matchPairs renders only the non-empty policy match fields (the API
      // emits zero values for unused predicates).
      matchPairs(p) {
        const out = {};
        for (const [k, v] of Object.entries((p && p.match) || {})) {
          if (v === null || v === undefined || v === "") continue;
          if (Array.isArray(v) && !v.length) continue;
          out[k] = Array.isArray(v) ? v.join(",") : v;
        }
        return out;
      },
      fleetNav() {
        return [
          { key: "fleet", label: "Fleet Management", icon: "▦", cap: "hosts" },
          { key: "execute", label: "Execute", icon: "❯", cap: "exec" },
          { key: "audit", label: "Audit Log", icon: "≡", cap: "audit" },
          { key: "sessions", label: "Sessions", icon: "▤", cap: "sessions" },
          { key: "files", label: "Files", icon: "🗀", cap: "files" },
          { key: "jobs", label: "Jobs", icon: "◷", cap: "jobs" },
          { key: "tasks", label: "Tasks & Playbooks", icon: "⚙", cap: "tasks" },
          { key: "updates", label: "Updates", icon: "⇪", cap: "packages" },
          { key: "secrets", label: "Secrets", icon: "🔒", cap: "secrets" },
          { key: "policies", label: "Policies", icon: "§", cap: "policies" },
          { key: "provision", label: "Provision", icon: "➕", cap: "provision", admin: true },
          { key: "users", label: "Users", icon: "👤", cap: "users", admin: true },
        ];
      },
      obsNav() {
        return [
          { key: "obs-services", label: "Services", icon: "◈" },
          { key: "obs-certs", label: "Certificates", icon: "✦" },
          { key: "obs-configs", label: "Configs", icon: "⌘" },
          { key: "obs-alerts", label: "Alerts", icon: "⚠", placeholder: "M6" },
        ];
      },
      navEnabled(n) { return this.capOn(n.cap) && (!n.admin || this.isAdmin); },
      navTitle(n) {
        if (n.placeholder) return "Not yet available — " + n.placeholder;
        if (n.admin && !this.isAdmin) return "Requires admin role";
        if (!this.capOn(n.cap)) return "Not yet available — " + n.cap + " not in this build";
        return "";
      },
      navTag(n) {
        if (n.admin && !this.isAdmin) return "admin";
        if (!this.capOn(n.cap)) return "off";
        return "";
      },
      navClick(n) { if (this.navEnabled(n)) this.go(n.key); },
      go(path) { location.hash = "/" + path; },
      setScope(name) { this.scope = this.scope === name ? null : name; },
      async refreshCaps() { try { this.caps = await this.api("/capabilities"); } catch (e) { this.caps = {}; } },
      async loadMe() { try { this.me = await this.api("/auth/me"); } catch (e) { } },
      async loadGroups() { try { this.groups = (await this.api("/groups")) || []; } catch (e) { this.groups = []; } },
      async doLogin() {
        this.loginBusy = true; this.loginErr = "";
        try {
          const r = await fetch("/api/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(this.loginForm) });
          const d = await r.json();
          if (!r.ok) { this.loginErr = d.message || "invalid credentials"; return; }
          this.token = d.token; localStorage.setItem(LS_TOKEN, d.token);
          this.me = { username: d.username, role: d.role };
          await this.afterLogin();
        } catch (e) { this.loginErr = "login failed: " + e.message; }
        finally { this.loginBusy = false; }
      },
      async afterLogin() { await Promise.all([this.refreshCaps(), this.loadMe(), this.loadGroups()]); this.startSSE(); this.loadPageData(); },
      signOut() {
        this.token = ""; localStorage.removeItem(LS_TOKEN); this.me = null;
        this.stopSSE(); this.sseStatus = "disconnected"; this.go("fleet");
      },
      async changePassword() {
        this.pwMsg = ""; this.pwErr = "";
        try {
          await this.api("/auth/password", { method: "POST", body: { current: this.pw.current, new: this.pw.next } });
          this.pwMsg = "Password updated."; this.pw.current = ""; this.pw.next = "";
        } catch (e) { this.pwErr = e.message; }
      },
      startSSE() {
        this.stopSSE();
        this.sseStatus = "reconnecting";
        let opened = false;
        const es = new EventSource("/api/v1/events");
        this._es = es;
        es.onopen = () => {
          this.sseStatus = "connected";
          // Reconcile only on RE-connect: the first open follows the initial
          // page load (mounted/afterLogin already fetched); reloading here
          // would double every list request on every page load.
          if (opened) this.loadPageData();
          opened = true;
        };
        es.onerror = () => { this.sseStatus = "reconnecting"; };
        const kinds = ["host.state", "execution.state", "audit.event", "job.run", "task.run", "package.action", "session.data", "session.opened", "session.result", "session.interrupted", "file.action"];
        for (const k of kinds) es.addEventListener(k, (e) => { let p; try { p = JSON.parse(e.data); } catch (err) { p = e.data; } this.onSSEEvent(k, p); });
      },
      stopSSE() { if (this._es) { this._es.close(); this._es = null; } },
      onSSEEvent(kind) {
        if (kind === "host.state") this.loadHosts();
        else if (kind === "execution.state") { if (this.page === "execute") this.loadExecutions(); if (this.page === "exec") this.loadExecDetail(); }
        else if (kind === "audit.event" && this.page === "audit") this.loadAudit();
        else if (kind === "job.run" && this.page === "jobs") this.loadJobs();
        else if (kind === "task.run" && this.page === "tasks") { this.loadTasks(); this.loadPlaybooks(); }
        else if (kind === "package.action" && this.page === "updates") this.loadUpdates();
        else if (kind === "file.action" && this.page === "files") this.listFiles();
        else if ((kind === "session.data" || kind === "session.result") && this.page === "session") this.loadSessionReplay();
      },
      async loadPageData() {
        // Files, Updates, and Jobs need the host list (default host selection,
        // per-host run target). Load it first if a deep link lands here before
        // the fleet page ever ran.
        if (["files", "updates", "jobs"].includes(this.page) && !this.hosts.length) {
          await this.loadHosts();
        }
        switch (this.page) {
          case "fleet": await this.loadHosts(); break;
          case "host": await this.loadHostDetail(); break;
          case "execute": await this.loadExecutions(); break;
          case "exec": await this.loadExecDetail(); break;
          case "audit": await this.loadAudit(); break;
          case "sessions": await this.loadSessions(); break;
          case "session": await this.loadSessionReplay(); break;
          case "files": await this.listFiles(); break;
          case "jobs": await this.loadJobs(); break;
          case "tasks": await this.loadTasks(); await this.loadPlaybooks(); break;
          case "updates": await this.loadUpdates(); break;
          case "secrets": await this.loadSecrets(); break;
          case "policies": await this.loadPolicies(); break;
          case "provision": await this.loadProvRuns(); break;
          case "users": await this.loadUsers(); break;
          case "obs-services": await this.loadServices(); break;
          case "obs-certs": await this.loadCerts(); break;
          case "obs-configs": await this.loadConfigs(); break;
        }
      },
      async loadHosts() { this.hostsLoading = true; try { const d = await this.api("/hosts"); this.hosts = d.items || []; } catch (e) { this.hosts = []; } finally { this.hostsLoading = false; } },
      async loadHostDetail() {
        // Overview comes from GET /hosts/{id} (state/uuid/version/timestamps);
        // GET /hosts/{id}/facts only returns {host_id, ts, facts}.
        try { this.host = await this.api("/hosts/" + encodeURIComponent(this.p1)); } catch (e) { this.host = null; }
        try { this.hostFacts = await this.api("/hosts/" + encodeURIComponent(this.p1) + "/facts"); } catch (e) { this.hostFacts = null; }
        try { this.hostEol = await this.api("/hosts/" + encodeURIComponent(this.p1) + "/eol"); } catch (e) { this.hostEol = null; }
      },
      async loadExecutions() { try { const d = await this.api("/executions"); this.executions = d.items || []; } catch (e) { this.executions = []; } },
      async loadExecDetail() {
        try { this.execDetail = await this.api("/executions/" + encodeURIComponent(this.p1)); } catch (e) { this.execDetail = null; return; }
        try { this.execOutput = (await this.api("/executions/" + encodeURIComponent(this.p1) + "/output")) || []; } catch (e) { this.execOutput = []; }
      },
      outFor(runId) { return this.execOutput.filter(o => o.run_id === runId); },
      async loadAudit() { const q = this.auditKind ? "?kind=" + encodeURIComponent(this.auditKind) : ""; try { const d = await this.api("/audit" + q); this.audit = d.items || []; } catch (e) { this.audit = []; } },
      async loadSessions() { try { const d = await this.api("/sessions"); this.sessions = d.sessions || d.items || []; } catch (e) { this.sessions = []; } },
      async loadSessionReplay() { try { this.sessionReplay = await this.api("/sessions/" + encodeURIComponent(this.p1) + "/replay"); } catch (e) { this.sessionReplay = null; } },
      replayText() {
        const fr = this.sessionReplay && this.sessionReplay.frames;
        if (!fr) return (this.sessionReplay ? JSON.stringify(this.sessionReplay) : "");
        let out = "";
        for (const f of fr) { try { out += decodeURIComponent(escape(atob(f.data_b64))); } catch (e) { out += atob(f.data_b64); } }
        return out || "(empty recording)";
      },
      async listFiles() {
        // /files/list requires agent_id and path (400 otherwise). Keep a host
        // selected once loaded so the page never fires a doomed request.
        if (!this.fileHost && this.hosts.length) this.fileHost = this.hosts[0].id;
        if (!this.fileHost) { this.fileEntries = []; return; }
        this.fileLoading = true;
        try { const q = "?agent_id=" + encodeURIComponent(this.fileHost) + "&path=" + encodeURIComponent(this.fileDir || "/"); const d = await this.api("/files/list" + q); this.fileEntries = d.entries || []; }
        catch (e) { this.fileEntries = []; } finally { this.fileLoading = false; }
      },
      async loadJobs() { try { const d = await this.api("/jobs"); this.jobs = d.items || d || []; } catch (e) { this.jobs = []; } },
      async loadTasks() { try { const d = await this.api("/tasks"); this.tasks = d.items || d || []; } catch (e) { this.tasks = []; } },
      async loadPlaybooks() { try { const d = await this.api("/playbooks"); this.playbooks = d.items || d || []; } catch (e) { this.playbooks = []; } },
      async loadUpdates() {
        // /packages/updates is per-host and REQUIRES agent_id; there is no
        // fleet-wide endpoint. Default to the first host when none is chosen.
        if (!this.updHost && this.hosts.length) this.updHost = this.hosts[0].id;
        if (!this.updHost) { this.updates = []; return; }
        try { const d = await this.api("/packages/updates?agent_id=" + encodeURIComponent(this.updHost)); this.updates = d.items || d || []; } catch (e) { this.updates = []; }
      },
      async loadSecrets() { try { const d = await this.api("/secrets"); this.secrets = d.secrets || d.items || []; } catch (e) { this.secrets = []; } },
      async loadPolicies() { try { const d = await this.api("/policies"); this.policies = d.items || d || []; } catch (e) { this.policies = []; } },
      async loadProvRuns() { try { const d = await this.api("/provision-runs"); this.provRuns = d.items || d || []; } catch (e) { this.provRuns = []; } },
      async loadUsers() { try { const d = await this.api("/users"); this.users = d.items || d || []; } catch (e) { this.users = []; } },
      async loadServices() { try { const d = await this.api("/services" + buildQ({ label: this.svcLabel, state: this.svcState })); this.services = d.items || []; } catch (e) { this.services = []; } },
      async loadCerts() { try { const d = await this.api("/certificates" + buildQ({ days_remaining_lt: this.certDays })); this.certs = d.items || []; } catch (e) { this.certs = []; } },
      async loadConfigs() { try { const d = await this.api("/configs" + buildQ({ kind: this.cfgKind })); this.configs = d.items || []; } catch (e) { this.configs = []; } },
      async previewSelector() {
        this.previewLoading = true; this.preview = null;
        try { this.preview = await this.api("/hosts?selector=" + encodeURIComponent(this.exSel)); }
        catch (e) { this.preview = { error: e.message }; } finally { this.previewLoading = false; }
      },
      async dispatch() {
        const args = this.exArgs.split(/\s+/).map(s => s.trim()).filter(Boolean);
        const body = { selector: this.exSel, cmd: this.exCmd };
        if (args.length) body.args = args;
        if (this.exTimeout) body.timeout_s = this.exTimeout;
        try { const d = await this.api("/executions", { body }); const id = d.execution_id || d.id; this.exCmd = ""; this.preview = null; if (id) this.go("exec/" + id); }
        catch (e) { alert("dispatch failed: " + e.message); }
      },
      async cancelExec(id) { try { await this.api("/executions/" + encodeURIComponent(id) + "/cancel", { method: "POST" }); this.loadExecDetail(); } catch (e) { alert(e.message); } },
      async runJob(job) {
        // POST /jobs/{id}/run requires an explicit agent_id.
        if (!this.hosts.length) { alert("No hosts available to run this job on."); return; }
        const agent = this.hosts.length === 1 ? this.hosts[0].id : prompt("Run on which host?\n" + this.hosts.map(h => h.id).join("\n"), this.hosts[0].id);
        if (!agent) return;
        try { await this.api("/jobs/" + encodeURIComponent(job.id) + "/run", { method: "POST", body: { agent_id: agent } }); } catch (e) { alert(e.message); }
      },
      openFile(f) { if (f.is_dir) { this.fileDir = joinPath(this.fileDir, f.name); this.listFiles(); } },
      fileUp() { this.fileDir = parentPath(this.fileDir); this.listFiles(); },
      pickFileHost(id) { this.fileHost = id; this.fileDir = "/"; this.listFiles(); },
      async createGroup() {
        const name = prompt("Group name:"); if (!name) return;
        const selector = prompt("Selector (all | host:ag_x | group:db):", "all"); if (!selector) return;
        try { await this.api("/groups", { body: { name, selector } }); this.loadGroups(); } catch (e) { alert(e.message); }
      },
      async deleteSecret(n) { if (confirm("Delete secret '" + n + "'?")) { try { await this.api("/secrets/" + encodeURIComponent(n), { method: "DELETE" }); this.loadSecrets(); } catch (e) { alert(e.message); } } },
      async deletePolicy(id) { if (confirm("Delete policy " + id + "?")) { try { await this.api("/policies/" + encodeURIComponent(id), { method: "DELETE" }); this.loadPolicies(); } catch (e) { alert(e.message); } } },
      async deleteUser(n) { if (confirm("Delete user '" + n + "'?")) { try { await this.api("/users/" + encodeURIComponent(n), { method: "DELETE" }); this.loadUsers(); } catch (e) { alert(e.message); } } },
    },
    created() {
      window.addEventListener("hashchange", () => { this.route = (location.hash || "#/fleet").replace(/^#\/?/, ""); });
    },
    mounted() {
      if (this.token) {
        Promise.all([this.refreshCaps(), this.loadMe(), this.loadGroups()]).then(() => {
          if (!this.me) { this.signOut(); return; }
          this.startSSE(); this.loadPageData();
        });
      }
    },
    beforeUnmount() { this.stopSSE(); },
    watch: {
      page() { this.loadPageData(); },
      p1() { if (["host", "exec", "session"].includes(this.page)) this.loadPageData(); },
    },
  });

  app.config.errorHandler = (err) => { console.error("partout ui:", err); };
  app.mount("#app");
})();
