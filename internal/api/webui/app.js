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
  const LS_NAV_COLLAPSED = "partout_nav_collapsed";
  const LS_THEME = "partout_theme";

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
  function taskRunBadge(s) { return ({ ok: "ok", changed: "ok", running: "info", rebooting: "info", failed: "bad", skipped: "neutral", denied: "outline-bad", awaiting_approval: "warn" })[s] || "neutral"; }
  function stepBadge(s) { return ({ ok: "ok", changed: "ok", failed: "bad", skipped: "neutral", rebooting: "info" })[s] || "neutral"; }
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
  function pkgActionBadge(s) { return ({ succeeded: "ok", ok: "ok", dry_run: "neutral", dry: "neutral", running: "info", failed: "bad", denied: "outline-bad", approval_required: "warn" })[s] || "neutral"; }
  function provBadge(s) {
    const m = { enrolled: { cls: "ok", label: "enrolled" }, completed: { cls: "ok", label: "completed" }, failed: { cls: "bad", label: "failed" }, cancelled: { cls: "neutral", label: "cancelled" }, handoff: { cls: "neutral", label: "handoff" }, key_confirm: { cls: "warn", label: "key confirm" } };
    return m[s] || { cls: "info", label: s || "running" };
  }
  function provStepBadge(s) { return ({ ok: "ok", done: "ok", succeeded: "ok", running: "info", failed: "bad", skipped: "neutral", cancelled: "neutral", pending: "neutral" })[s] || "neutral"; }
  // firstLine bounds a (possibly multi-line) error to a single short line for toasts.
  function firstLine(s) { return String(s || "").split(/\r?\n/)[0].slice(0, 300); }
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
  // b64FromBytes base64-encodes a Uint8Array in chunks (btoa on one huge
  // string overflows the stack for large files).
  function b64FromBytes(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    return btoa(bin);
  }
  function parentPath(p) { const s = (p || "/").replace(/\/+$/, ""); const i = s.lastIndexOf("/"); return i <= 0 ? "/" : s.slice(0, i); }
  function obj(v) { try { return v ? JSON.parse(v) : null; } catch (e) { return v; } }
  // Human-friendly host label: the server already computes h.name, but these
  // fallbacks keep the UI correct for older/partial host objects (e.g. the
  // selector preview shape, which has no name field).
  function hostName(h) {
    if (!h) return "";
    if (h.name) return h.name;
    if (h.hostname) return h.hostname;
    if (h.tags && h.tags.name) return h.tags.name;
    if (h.roles && h.roles.length) return h.roles[0];
    return h.id || "";
  }
  function hostOption(h) {
    if (!h) return "";
    const n = hostName(h);
    return n && n !== h.id ? n + " (" + h.id + ")" : (h.id || "");
  }

  class ApiError extends Error { constructor(status, message, code, data) { super(message); this.status = status; this.code = code; this.data = data; } }

  const TEMPLATE = `
  <!-- ============ TOASTS ============ -->
  <div class="toasts" aria-live="polite">
    <div v-for="t in toasts" :key="t.id" class="toast" :class="t.kind">
      <span class="toast-msg">{{ t.msg }}</span>
      <button class="toast-x" @click="dismissToast(t.id)" aria-label="dismiss">×</button>
    </div>
  </div>
  <!-- ============ ADD HOST DIALOG (Fleet) ============ -->
  <div class="overlay" v-if="addHostOpen && loggedIn" @click.self="closeAddHost()">
    <div class="dialog card">
      <div class="head">
        <h2>Add host</h2>
        <p class="cap">Two ways to bring a host under management. Pick the one that fits your access.</p>
        <div class="spacer"></div>
        <button class="btn sm" @click="closeAddHost()" aria-label="close">✕</button>
      </div>
      <div class="tabs">
        <div class="tab" :class="{active: addHostTab==='manual'}" @click="addHostTab='manual'">Run on the host</div>
        <div class="tab" :class="{active: addHostTab==='ssh'}" @click="addHostTab='ssh'" :title="isAdmin ? '' : 'requires admin role'">Onboard over SSH</div>
      </div>

      <!-- Option A: manual install with a one-time enrollment token -->
      <div v-if="addHostTab==='manual'">
        <p class="cap">For hosts you can shell into that the server should not SSH into. Mint a
          one-time token, run the command on the host — it appears in the fleet the moment it connects.</p>
        <div v-if="!ahToken">
          <button class="btn primary sm" :disabled="!isOperator || ahTokenBusy" @click="mintAddHostToken()">Mint one-time token (15 min)</button>
          <span v-if="!isOperator" class="muted small" style="margin-left:8px">requires operator role</span>
        </div>
        <div v-else>
          <div class="console" style="white-space:pre-wrap;word-break:break-all">{{ ahCmd }}</div>
          <div class="toolbar" style="margin-top:8px">
            <button class="btn sm" @click="copyAhCmd">Copy command</button>
            <span class="muted small">shown once — expires in {{ ahTtlLeft }} s</span>
          </div>
          <p class="muted small" style="margin-top:8px">The <span class="mono">partout</span> binary ships as a static
            linux build in each release. If this UI is behind a proxy, replace
            <span class="mono">{{ locationHost }}</span> with an address the host can actually reach.</p>
        </div>
      </div>

      <!-- Option B: server-side provisioning over the operator's fleet SSH -->
      <div v-else>
        <p class="cap">The server installs the agent over your existing fleet SSH — the
          <b>server's own</b> <span class="mono">~/.ssh</span> must reach <span class="mono">user@host</span>.
          A new host key pauses the run at <span class="mono">key_confirm</span> until you confirm its fingerprint.</p>
        <div class="toolbar">
          <input v-model="provHost" class="mono" placeholder="user@host" style="max-width:200px" />
          <select v-model="provMode">
            <option value="fresh" title="fresh: clean slate — stops and removes any existing partout agent + identity on the host, then enrolls a brand-new agent">fresh</option>
            <option value="join" title="join: non-destructive in-place binary update for a host that already has an enrolled agent (identity preserved)">join</option>
          </select>
          <button class="btn primary sm" :disabled="!isAdmin || !provHost || !!provBusy" @click="createProvRun()">Start</button>
          <span v-if="!isAdmin" class="muted small">requires admin role</span>
        </div>
        <p class="muted small" style="margin-top:8px">{{ provModeHint }}</p>
      </div>
    </div>
  </div>
  <!-- ============ ONBOARD WIZARD (guided SSH provisioning) ============ -->
  <div class="overlay" v-if="provWiz.open && loggedIn" @click.self="provWizClose()">
    <div class="dialog card" style="max-width:660px">
      <div class="head">
        <h2>Onboard a host</h2>
        <span class="muted small" style="margin-left:12px">{{ provWizPhaseLabel }}</span>
        <div class="spacer"></div>
        <button class="btn sm" @click="provWizClose()" aria-label="close">✕</button>
      </div>

      <!-- PHASE: target -->
      <div v-if="provWiz.phase==='target'">
        <p class="cap">Bring a Linux host under management over your existing SSH access.</p>
        <div class="form-row" style="align-items:flex-end">
          <label class="fld" style="flex:1"><span>Host</span><input v-model="provWiz.host" class="mono" placeholder="user@host" @keyup.enter="provWizNext()" /></label>
          <label class="fld" style="max-width:220px"><span>Mode</span>
            <select v-model="provWiz.mode">
              <option value="fresh">fresh — new agent</option>
              <option value="join">join — update existing</option>
            </select>
          </label>
        </div>
        <p class="muted small" style="margin-top:8px">{{ provWizModeHint }}</p>
        <p v-if="provWizKnownHost" class="small" style="margin-top:6px">
          <template v-if="provWiz.mode==='fresh'">
            <span style="color:var(--warning,#d97706);font-weight:600">⚠ {{ provWizKnownHost }} looks already enrolled.</span>
            <span class="muted"> fresh will stop and remove its existing agent + identity — choose <b>join</b> to preserve it.</span>
          </template>
          <template v-else>
            <span class="muted">ℹ <b class="mono">{{ provWizKnownHost }}</b> looks already enrolled — join updates it in place, preserving its identity.</span>
          </template>
        </p>
        <div class="toolbar" style="margin-top:14px">
          <span v-if="!isAdmin" class="muted small">requires admin role</span>
          <div class="spacer"></div>
          <button class="btn sm" @click="provWizClose()">Cancel</button>
          <button class="btn primary sm" :disabled="!isAdmin || !provWiz.host.trim()" @click="provWizNext()">Continue</button>
        </div>
      </div>

      <!-- PHASE: confirm -->
      <div v-else-if="provWiz.phase==='confirm'">
        <p class="cap">Confirm the onboarding plan for <b class="mono">{{ provWiz.host }}</b>.</p>
        <table class="tbl">
          <tbody>
            <tr><td class="muted" style="width:130px">Target</td><td class="mono">{{ provWiz.host }}</td></tr>
            <tr><td class="muted">Mode</td><td>{{ provWiz.mode }} <span class="muted small">— {{ provWizModeShort }}</span></td></tr>
            <tr><td class="muted">SSH access</td><td>
              <template v-if="provWiz.sshBusy"><span class="muted small">checking…</span></template>
              <template v-else-if="provWiz.sshStatus && (provWiz.sshStatus.file_keys||[]).length">
                <span class="mono">{{ provWiz.sshStatus.ssh_dir }}/{{ provWiz.sshStatus.file_keys[0] }}</span>
                <span class="muted small"> — conventional key found</span>
              </template>
              <template v-else-if="provWiz.sshStatus && provWiz.sshStatus.agent">
                <b>ssh-agent</b> <span class="muted small">holds a key (no conventional file in <span class="mono">{{ provWiz.sshStatus.ssh_dir }}</span>)</span>
              </template>
              <template v-else-if="provWiz.sshErr">
                <span class="muted small">unavailable ({{ provWiz.sshErr }})</span>
              </template>
              <template v-else-if="provWiz.sshStatus">
                <span style="color:var(--critical, #dc2626);font-weight:600">no identity key found</span>
                <span class="muted small"> in <span class="mono">{{ provWiz.sshStatus.ssh_dir }}</span> or the ssh-agent — add a key or provisioning will fail</span>
              </template>
              <template v-else><span class="muted small">…</span></template>
              <span class="muted small"> — nothing created or stored</span>
            </td></tr>
            <tr><td class="muted">Host key</td><td>a new key pauses for your confirmation first (no silent TOFU)</td></tr>
            <tr><td class="muted">Steps</td><td class="mono small">connect → preflight → transfer → install → wait-enroll</td></tr>
          </tbody>
        </table>
        <div class="toolbar" style="margin-top:14px">
          <div class="spacer"></div>
          <button class="btn sm" @click="provWiz.phase='target'">Back</button>
          <button class="btn primary sm" :disabled="!!provWiz.busy" @click="provWizStart()"><span v-if="provWiz.busy" class="spin"></span>Start provisioning</button>
        </div>
      </div>

      <!-- PHASE: live -->
      <div v-else-if="provWiz.phase==='live' && provWiz.run">
        <div class="toolbar">
          <span class="badge" :class="provBadge(provWiz.run.state).cls" style="font-size:13px">{{ provBadge(provWiz.run.state).label }}</span>
          <span class="mono muted small">{{ provWiz.run.host }} · {{ provWiz.run.mode }}</span>
          <span v-if="provWiz.run.step && !provTerminal(provWiz.run.state)" class="muted small">→ {{ provWiz.run.step }}</span>
        </div>

        <div v-if="provWiz.run.state==='key_confirm'" class="info-box" style="margin-top:12px;border-left:3px solid var(--warn,#d97706)">
          <div style="font-weight:600">New host key — confirm to continue</div>
          <div class="mono" style="margin:8px 0;word-break:break-all">{{ provWiz.run.key_type || '' }} {{ provWiz.run.fingerprint }}</div>
          <p class="muted small" style="margin:0 0 10px">Verify this fingerprint out-of-band before confirming.</p>
          <button class="btn ok sm" @click="provWizKey('confirm')">Confirm key</button>
          <button class="btn danger sm" @click="provWizKey('deny')">Deny</button>
        </div>

        <div v-if="provWiz.run.error" class="err-box" style="margin-top:12px">{{ provWiz.run.error }}</div>

        <div v-if="provWizStalled" class="info-box" style="margin-top:12px;border-left:3px solid var(--warning,#d97706)">
          <div style="font-weight:600">No state change for {{ Math.max(1, Math.floor((Date.now()/1000 - provWiz.run.updated)/60)) }}+ min</div>
          <p class="muted small" style="margin:4px 0 0">This run may be stuck. Cancel it and start a fresh run — the reason will be shown in the Runs table.</p>
        </div>

        <table class="tbl" style="margin-top:12px">
          <thead><tr><th>#</th><th>Step</th><th>State</th><th>Output excerpt</th></tr></thead>
          <tbody>
            <tr v-for="s in provWiz.steps" :key="s.seq">
              <td class="mono">{{ s.seq }}</td><td class="mono">{{ s.name }}</td>
              <td><span class="badge" :class="provStepBadge(s.state)">{{ s.state }}</span></td>
              <td class="mono small" style="max-width:300px;overflow:hidden;text-overflow:ellipsis" tabindex="0" :data-jtip="s.stderr_excerpt || s.stdout_excerpt || ''">{{ s.stderr_excerpt || s.stdout_excerpt || '—' }}</td>
            </tr>
            <tr v-if="!(provWiz.steps||[]).length"><td colspan="4" class="muted">Connecting…</td></tr>
          </tbody>
        </table>

        <div v-if="provTerminal(provWiz.run.state)" class="info-box" style="margin-top:12px">
          <template v-if="provWiz.run.state==='connected' || provWiz.run.state==='handoff'">
            <b>Host enrolled.</b>
            <a v-if="provWiz.run.agent_id" @click.prevent="provWizOpenHost()" class="mono" style="margin-left:6px">{{ provWiz.run.agent_id }}</a>
            <span v-if="provWiz.run.agent_id"> → open in Fleet</span>
          </template>
          <template v-else-if="provWiz.run.state==='failed'">Provisioning failed — see the error above.</template>
          <template v-else-if="provWiz.run.state==='cancelled'">Provisioning cancelled.</template>
        </div>

        <div class="toolbar" style="margin-top:14px">
          <button v-if="!provTerminal(provWiz.run.state)" class="btn danger sm" @click="provWizCancel()">Cancel run</button>
          <div class="spacer"></div>
          <button v-if="provTerminal(provWiz.run.state)" class="btn primary sm" @click="provWizClose()">Close</button>
          <button v-else class="btn sm" @click="provWizClose()">Minimize</button>
        </div>
      </div>
    </div>
  </div>
  <!-- ============ FILE DIALOG (view / edit-CAS / perm) ============ -->
  <div class="overlay" v-if="fileDlg && fileDlg.open && loggedIn" @click.self="fileDlg.open = false">
    <div class="dialog card" style="max-width:780px">
      <div class="head">
        <h2>{{ fileDlg.name }}</h2>
        <span class="muted mono small" style="margin-left:8px">{{ hostNameById(fileDlg.host) }} : {{ fileDlg.path }}</span>
        <div class="spacer"></div>
        <button class="btn sm" @click="fileDlg.open = false" aria-label="close">✕</button>
      </div>
      <div v-if="fileDlg.loading" class="muted" style="padding:18px 0">Loading…</div>
      <template v-else-if="fileDlg.stat">
        <div class="muted small mono" style="margin-bottom:8px">
          {{ fmtBytes(fileDlg.stat.size) }} · mode {{ fileDlg.stat.mode }} · {{ fileDlg.stat.owner }}:{{ fileDlg.stat.group }} · sha256 {{ (fileDlg.origSha || '').slice(0, 12) }}…
        </div>
        <div v-if="fileDlg.err" class="err-box" style="margin-bottom:8px">{{ fileDlg.err }}</div>
        <template v-if="!fileDlg.binary && !fileDlg.tooLarge">
          <textarea v-model="fileDlg.content" spellcheck="false" rows="14" @input="fileDlg.dirty = true" style="width:100%;box-sizing:border-box;font-family:var(--mono,monospace);font-size:12px;line-height:1.45;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--surface-app);color:var(--text)"></textarea>
          <p class="muted small" style="margin:6px 0 0">Compare-and-swap against sha256 {{ (fileDlg.origSha || '').slice(0, 12) }}… — the save aborts if the file changed on the host since you opened it. Inline edit cap: 1 MiB.</p>
        </template>
        <div v-else class="info-box" style="margin-bottom:8px">
          {{ fileDlg.tooLarge ? 'Larger than the 1 MiB inline-edit cap — use Download, or Upload a replacement.' : 'Binary file — no inline editor; use Download, or Upload a replacement.' }}
        </div>
        <div class="toolbar" style="margin-top:12px">
          <label class="fld" style="margin:0"><span>Mode</span><input v-model="fileDlg.mode" class="mono" style="width:70px" placeholder="0644" /></label>
          <label class="fld" style="margin:0"><span>Owner</span><input v-model="fileDlg.owner" class="mono" style="width:90px" placeholder="—" /></label>
          <label class="fld" style="margin:0"><span>Group</span><input v-model="fileDlg.group" class="mono" style="width:90px" placeholder="—" /></label>
          <button class="btn sm" :disabled="!isOperator || fileDlg.permBusy" @click="fileDlgPerm()"><span v-if="fileDlg.permBusy" class="spin"></span>Apply perm</button>
          <div class="spacer"></div>
          <button class="btn sm" :disabled="fileDlg.loading" @click="fileDlgReload()">Reload</button>
          <button v-if="!fileDlg.binary && !fileDlg.tooLarge" class="btn primary sm" :disabled="!isOperator || fileDlg.busy || !fileDlg.dirty" @click="fileDlgSave()"><span v-if="fileDlg.busy" class="spin"></span>Save (CAS)</button>
        </div>
      </template>
      <div v-else class="muted" style="padding:18px 0">Unreadable (see error above, or the host is offline).</div>
    </div>
  </div>

  <!-- ============ FILE UPLOAD DIALOG ============ -->
  <div class="overlay" v-if="upDlg && upDlg.open && loggedIn" @click.self="upDlg.open = false">
    <div class="dialog card" style="max-width:560px">
      <div class="head">
        <h2>Upload file</h2>
        <span class="muted mono small" style="margin-left:8px">{{ hostNameById(fileHost) }}</span>
        <div class="spacer"></div>
        <button class="btn sm" @click="upDlg.open = false" aria-label="close">✕</button>
      </div>
      <p class="cap">Ship a local file to the host (atomic write; overwrites any existing file at the target path). Policy-gated (<span class="mono">file.write</span>), audited. Server cap: 256 MiB.</p>
      <div v-if="upDlg.err" class="err-box" style="margin:10px 0">{{ upDlg.err }}</div>
      <div class="form-row" style="align-items:flex-end">
        <label class="fld" style="flex:1"><span>Local file</span>
          <input type="file" @change="upDlgFilePicked($event)" />
        </label>
      </div>
      <div class="form-row" style="align-items:flex-end;margin-top:8px">
        <label class="fld" style="flex:1"><span>Target path</span><input v-model="upDlg.path" class="mono" :placeholder="fileDir || '/'" /></label>
        <label class="fld" style="max-width:110px"><span>Mode</span><input v-model="upDlg.mode" class="mono" /></label>
      </div>
      <div class="toolbar" style="margin-top:14px">
        <div class="spacer"></div>
        <button class="btn sm" @click="upDlg.open = false">Cancel</button>
        <button class="btn primary sm" :disabled="!isOperator || !upDlg.file || !upDlg.path.trim() || upDlg.busy" @click="upDlgGo()"><span v-if="upDlg.busy" class="spin"></span>Upload</button>
      </div>
    </div>
  </div>

  <!-- ============ CONFIRM DIALOG (replaces native confirm()) ============ -->
  <div class="overlay" v-if="confirmBox.open && loggedIn" @click.self="confirmBoxNo()">
    <div class="dialog card" style="max-width:520px">
      <div class="head"><h2>{{ confirmBox.title }}</h2></div>
      <p v-if="confirmBox.body" class="small" style="line-height:1.55;white-space:pre-line">{{ confirmBox.body }}</p>
      <div v-if="confirmBox.mono" class="mono" style="margin:10px 0;padding:8px 10px;background:var(--surface-app);border:1px solid var(--border);border-radius:8px;word-break:break-all">{{ confirmBox.mono }}</div>
      <div v-if="confirmBox.requireText" class="fld" style="margin-top:10px">
        <span>Type <span class="mono">{{ confirmBox.requireText }}</span> to confirm</span>
        <input v-model="confirmBox.value" class="mono" :placeholder="confirmBox.requireText" @keyup.enter="confirmBoxAllowed() && confirmBoxYes()" />
      </div>
      <div v-if="confirmBox.inputLabel" class="fld" style="margin-top:10px">
        <span>{{ confirmBox.inputLabel }}</span>
        <input v-model="confirmBox.input" :type="confirmBox.inputType" :placeholder="confirmBox.inputPlaceholder" @keyup.enter="confirmBoxYes()" />
      </div>
      <div class="toolbar" style="margin-top:16px">
        <div class="spacer"></div>
        <button class="btn sm" @click="confirmBoxNo()" style="margin-right:8px">Cancel</button>
        <button class="btn sm" :class="confirmBox.variant" :disabled="!confirmBoxAllowed()" @click="confirmBoxYes()">{{ confirmBox.confirmLabel }}</button>
      </div>
    </div>
  </div>
  <!-- ============ COMMAND PALETTE (⌘K / Ctrl-K) ============ -->
  <div class="overlay palette-overlay" v-if="paletteOpen && loggedIn" @click.self="closePalette()">
    <div class="dialog card palette">
      <input ref="paletteInput" v-model="paletteQ" class="palette-input" placeholder="Jump to a page or host…"
             @keydown.down.prevent="paletteMove(1)" @keydown.up.prevent="paletteMove(-1)"
             @keydown.enter.prevent="paletteRun()" @keydown.esc.prevent="closePalette()" />
      <div class="palette-list">
        <div v-for="(it, i) in paletteItems" :key="it.kind + ':' + it.key" class="palette-item"
             :class="{active: i===paletteIdx}" @click="paletteGo(it)" @mousemove="paletteIdx=i">
          <span class="palette-kind">{{ it.kind === 'host' ? 'Host' : it.group }}</span>
          <span class="palette-label">{{ it.icon }} {{ it.label }}</span>
          <span v-if="it.sub" class="palette-sub mono">{{ it.sub }}</span>
        </div>
        <div v-if="!paletteItems.length" class="palette-empty">No matches</div>
      </div>
    </div>
  </div>
  <!-- ============ LOGIN ============ -->
  <div v-if="!loggedIn" class="login-wrap">
    <div class="login-card">
      <div class="brand" style="padding:0 0 16px">
        <div class="logo">P</div>
        <div><div class="word">Partout</div><div class="sub">Fleet Management</div></div>
      </div>
      <div v-if="cleartextLogin" class="warn-box" style="margin-bottom:14px">
        ⚠ This connection is not encrypted. Your password and session tokens
        will cross the network in cleartext. Enable TLS on the server
        (<span class="mono">PARTOUT_TLS=on</span> — a local root CA is bootstrapped on first run)
        or put it behind a TLS proxy, then reload this page.
      </div>
      <form @submit.prevent="doLogin">
        <label class="fld"><span>Username</span><input v-model="loginForm.username" autocomplete="username" autofocus /></label>
        <label class="fld"><span>Password</span><input v-model="loginForm.password" type="password" autocomplete="current-password" /></label>
        <div v-if="loginErr" class="err-box" style="margin-bottom:12px">{{ loginErr }}</div>
        <button type="submit" class="btn primary" style="width:100%;justify-content:center" :disabled="loginBusy">
          <span v-if="loginBusy" class="spin"></span> Sign in
        </button>
      </form>
      <p class="muted small" style="margin-top:14px;line-height:1.5">
        <b>First run?</b> Sign in as <span class="mono">admin</span>. If you did not set
        <span class="mono">PARTOUT_ADMIN_PASSWORD</span>, the generated password was written to
        <span class="mono">admin_password.txt</span> next to the database on the server —
        log in, change it, then delete the file.
      </p>
    </div>
  </div>
  <!-- ============ SHELL ============ -->
  <div v-else class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="logo">P</div>
        <div><div class="word">Partout</div><div class="sub">Fleet Management</div></div>
        <div class="port" v-if="serverVersion" tabindex="0" :data-tip="'server ' + serverVersion">{{ serverVersion }}</div>
      </div>
      <nav class="nav">
        <template v-for="g in navGroups()" :key="g.key">
          <div class="nav-section" @click="toggleNavGroup(g.key)" :title="isNavCollapsed(g.key) ? 'Expand' : 'Collapse'">
            <span class="nav-caret">{{ isNavCollapsed(g.key) ? '▸' : '▾' }}</span>{{ g.label }}
            <span v-if="navGroupBadge(g) > 0" class="nav-badge">{{ navGroupBadge(g) }}</span>
          </div>
          <template v-if="!isNavCollapsed(g.key)">
            <div v-for="n in g.items" :key="n.key"
                 :class="['nav-item', {active: page===n.key, disabled: !navEnabled(n)}]"
                 :title="navTitle(n)" @click="navClick(n)">
              <span class="icon">{{ n.icon }}</span>{{ n.label }}
              <span v-if="n.badge && navBadge(n) > 0" class="nav-badge" :class="n.badge">{{ navBadge(n) }}</span>
              <span v-else-if="!navEnabled(n)" class="chip-ms">{{ navTag(n) }}</span>
            </div>
          </template>
        </template>

        <template v-if="groups.length">
          <div class="nav-section nav-section-plain">Scope</div>
          <div v-for="g in groups" :key="g.name" class="nav-scope" :class="{active: scope===g.name}"
               :title="'Filter the fleet to group #' + g.name + (scope === g.name ? ' (click to clear)' : '')"
               @click="setScope(g.name)">
            <span class="mono">#{{ g.name }}</span>
            <span v-if="scope === g.name" class="nav-clear">×</span>
          </div>
          <div v-if="scope" class="nav-scope-hint muted small" :class="{'scope-err': !!scopeErr}">
            {{ scopeErr ? scopeErr : (scopeHostIds ? scopeHostIds.length + ' host(s) in scope' : 'resolving…') }}
          </div>
        </template>
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
        <button class="btn sm ghost palette-btn" @click="openPalette" title="Jump to a page or host (⌘K / Ctrl-K)">
          <span class="kbd">⌘K</span> Jump to…
        </button>
        <button class="btn ghost theme-btn" :aria-label="theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'"
                :title="theme === 'dark' ? 'Light mode' : 'Dark mode'" @click="toggleTheme">
          <svg v-if="theme === 'dark'" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
          <svg v-else width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
        </button>
        <div class="sse-dot" data-tip-pos="below" :data-tip="'stream: /api/v1/events — ' + sseStatus">
          <span class="dot" :class="sseDot"></span>{{ sseStatus }}
        </div>
      </div>

      <div class="body" :class="{ 'sse-stale': sseWasConnected && sseStatus !== 'connected' }">
        <div v-if="sseWasConnected && sseStatus !== 'connected'" class="stale-banner">
          <b>Live updates paused</b> — data on this page may be stale.
          <template v-if="sseStatus === 'reconnecting'"> Reconnecting…</template>
          <template v-else> Stream down — check the server.</template>
        </div>
        <div v-if="pageLoading && pagePrimaryEmpty" class="loading-banner"><span class="spin"></span> Loading…</div>
        <div v-if="userMenu" @click="userMenu=false" style="position:fixed;inset:0;z-index:40;background:rgba(15,23,42,.25)">
          <div style="position:absolute;bottom:70px;left:12px;background:var(--surface);border:1px solid var(--border);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);padding:6px;min-width:180px">
            <div class="nav-item" @click.stop="userMenu=false; go('account')">Account</div>
            <div class="nav-item" @click.stop="signOut">Sign out</div>
          </div>
        </div>

        <!-- ============ FLEET ============ -->
        <section v-if="page==='fleet'">
          <h1 class="page">Fleet Management</h1>
          <p class="page-sub">{{ visibleHosts.length }} host{{ visibleHosts.length===1?'':'s' }}<template v-if="scope"> · scoped to <b>#{{ scope }}</b></template><template v-if="fleetFilter.trim()"> · filtered</template></p>
          <div class="grid cols-3" style="margin-bottom:16px">
            <div class="stat ok"><div class="lbl">🛡 Connected</div><div class="num">{{ health.connected }}</div></div>
            <div class="stat bad"><div class="lbl">✕ Disconnected</div><div class="num">{{ health.disconnected }}</div></div>
            <div class="stat info"><div class="lbl">◷ Pending</div><div class="num">{{ health.pending }}</div></div>
          </div>
          <div v-if="!hostsLoading && !hosts.length && !gsDismissed" class="card gs-card" style="margin-bottom:16px">
            <div class="head">
              <h2>Get started</h2>
              <div class="spacer"></div>
              <button class="btn sm" @click="dismissGettingStarted()" aria-label="dismiss">✕</button>
            </div>
            <ol class="gs-steps">
              <li class="gs-primary"><b>1 · Onboard your first host</b> — over your existing SSH (guided wizard) or a one-time token.
                <button class="btn primary sm" style="margin-left:8px" @click="go('provision')">Start onboarding →</button></li>
              <li><b>2 · Review the default guardrails</b> — the preset seeded safety-net policies and alert rules on first run.
                <a @click.prevent="go('policies')" class="gs-link">Policies</a><span class="muted"> · </span><a @click.prevent="go('obs-alerts')" class="gs-link">Alerts</a></li>
              <li><b>3 · Keep the fleet current</b> — upload a release and roll it out.
                <a @click.prevent="go('updates')" class="gs-link">Updates</a></li>
            </ol>
          </div>
          <div class="card">
            <div class="head"><h2>Hosts</h2>
              <input v-model="fleetFilter" class="fleet-filter" placeholder="Filter by name, id, role…" />
              <div class="spacer"></div>
              <button class="btn sm" @click="createGroup" :disabled="!isOperator">+ Group</button>
              <button class="btn primary sm" @click="openAddHost" :disabled="!isOperator">+ Add host</button>
            </div>
            <table class="tbl">
              <thead><tr><th>Host</th><th>State</th><th>OS</th><th>Version</th><th>Last seen</th></tr></thead>
              <tbody>
                <tr v-for="h in visibleHosts" :key="h.id" class="click" @click="go('host/'+h.id)">
                  <td>
                    <div class="host-name">{{ hostName(h) }}</div>
                    <div class="host-id mono muted" v-if="hostName(h) !== h.id">{{ h.id }}</div>
                    <div v-if="h.roles && h.roles.length" class="host-roles"><span class="chip" v-for="r in h.roles" :key="r">{{ r }}</span></div>
                  </td>
                  <td><span class="badge" :class="agentBadge(h.state).cls">{{ agentBadge(h.state).label }}</span></td>
                  <td class="muted">{{ h.os || '—' }}</td>
                  <td class="mono">{{ h.version || '—' }}</td>
                  <td class="muted">{{ fmtAgo(h.last_seen) }}</td>
                </tr>
                <tr v-if="!hostsLoading && !visibleHosts.length"><td colspan="5"><div class="empty"><div class="big">▦</div><template v-if="fleetFilter.trim()">No hosts match <b>{{ fleetFilter }}</b>.</template><template v-else-if="scope">No hosts in <b>#{{ scope }}</b>.</template><template v-else>No hosts enrolled yet.<div style="margin-top:10px"><button class="btn primary sm" :disabled="!isOperator" @click="openAddHost">Add your first host</button></div></template></div></td></tr>
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
                <div class="head" style="margin-bottom:6px">
                  <h2 style="margin:0">{{ hostName(host) || p1 }}</h2>
                  <div class="spacer"></div>
                  <button v-if="isAdmin" class="btn danger sm" :disabled="!host" @click="removeHost()" title="Delete the agent and all its data; the host can never rejoin with its current identity">Remove host</button>
                </div>
                <p class="cap mono muted" v-if="hostName(host) && hostName(host) !== p1">{{ p1 }}</p>
                <p class="cap">Host overview</p>
                <dl class="kv">
                  <dt>State</dt><dd><span class="badge" :class="agentBadge((host && host.state) || 'disconnected').cls">{{ agentBadge((host && host.state) || 'disconnected').label }}</span></dd>
                  <dt>UUID</dt><dd class="mono">{{ (host && host.uuid) || '—' }}</dd>
                  <dt>Version</dt><dd class="mono">{{ (host && host.version) || '—' }}</dd>
                  <dt>OS</dt><dd>{{ (host && host.os) || '—' }}</dd>
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
            <div class="card" v-if="isOperator">
              <h2>Labels &amp; roles</h2>
              <p class="cap">Operator-assigned identity: the display name and service tags drive the fleet
                display name; roles feed <span class="mono">role:</span> selectors. Saving an empty field clears it.</p>
              <div class="grid cols-2">
                <label class="fld"><span>Display name (tag <span class="mono">name</span>)</span>
                  <input v-model="labelDraft.name" placeholder="e.g. web-01-prod — falls back to hostname" /></label>
                <label class="fld"><span>Service (tag <span class="mono">service</span>)</span>
                  <input v-model="labelDraft.service" placeholder="e.g. haproxy" /></label>
              </div>
              <label class="fld"><span>Roles</span>
                <div class="toolbar">
                  <span class="muted small" v-if="!(host && host.roles && host.roles.length)">none</span>
                  <span class="chip" v-for="r in (host && host.roles) || []" :key="r">{{ r }}<a href="#" @click.prevent="removeRole(r)" title="remove role">×</a></span>
                  <input v-model="roleDraft" class="mono" placeholder="add role…" style="max-width:150px" @keyup.enter="addRole()" />
                </div>
              </label>
              <button class="btn primary sm" :disabled="labelBusy" @click="saveHostLabels()">
                <span v-if="labelBusy" class="spin"></span> Save name &amp; service
              </button>
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
                  <td class="mono">{{ hostNameById(r.agent_id) }}</td>
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
                  <td class="mono">{{ a.agent_id ? (hostNameById(a.agent_id) || a.agent_id) : 'server' }}</td>
                  <td class="mono small" style="max-width:420px;overflow:hidden;text-overflow:ellipsis">{{ typeof a.payload==='string'? a.payload : (a.payload && a.payload.message) || JSON.stringify(a.payload||{}) }}</td>
                </tr>
                <tr v-if="!audit.length && !pageLoading"><td colspan="5"><div class="empty">No audit events.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ SESSIONS ============ -->
        <section v-else-if="page==='sessions'">
          <h1 class="page">Sessions</h1>
          <p class="page-sub">PTY terminal sessions and recordings (M2).</p>
          <div class="card" style="margin-bottom:12px">
            <div class="head"><h2>Open terminal</h2><p class="cap">Live PTY (xterm.js): input via REST, output via SSE.</p></div>
            <div class="toolbar">
              <select v-model="ptyHost" style="max-width:200px">
                <option value="">host…</option>
                <option v-for="h in hosts" :key="h.id" :value="h.id">{{ hostOption(h) }}</option>
              </select>
              <input v-model="ptyCmd" class="mono" placeholder="bash" style="max-width:160px" />
              <button class="btn primary sm" :disabled="!isOperator || !ptyHost || !ptyCmd || ptyBusy" @click="openSession">
                <span v-if="ptyBusy" class="spin"></span> Open terminal
              </button>
              <span v-if="ptyErr" class="err-box" style="margin:0">{{ ptyErr }}</span>
            </div>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>ID</th><th>Host</th><th>Command</th><th>State</th><th></th></tr></thead>
              <tbody>
                <tr v-for="s in sessions" :key="s.id || s.session_id">
                  <td class="mono">{{ s.id || s.session_id }}</td>
                  <td class="mono">{{ hostNameById(s.agent_id || s.host_id) }}</td>
                  <td class="mono">{{ (s.cmd || (s.args && s.args.join(' '))) || 'shell' }}</td>
                  <td><span class="badge neutral">{{ s.state || '—' }}</span></td>
                  <td><button class="btn sm" @click="go('session/'+(s.id||s.session_id))">{{ (s.id||s.session_id)===p1 ? 'Open' : (s.state==='open' ? 'Attach' : 'Replay') }}</button></td>
                </tr>
                <tr v-if="!sessions.length && !pageLoading"><td colspan="5"><div class="empty">No sessions.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ SESSION (live terminal + replay) ============ -->
        <section v-else-if="page==='session'">
          <h1 class="page">Session <span class="mono muted">{{ p1 }}</span></h1>
          <div class="card" v-if="sessionLive && sessionLive.state==='open'">
            <div class="toolbar" style="margin-bottom:8px">
              <span class="badge info">live</span>
              <span class="mono small">{{ sessionLive.cmd }}<template v-if="sessionLive.args && sessionLive.args.length"> {{ sessionLive.args.join(' ') }}</template></span>
              <span class="muted mono small">on {{ hostNameById(sessionLive.agent_id) }}</span>
              <div class="spacer"></div>
              <button class="btn danger sm" :disabled="!isOperator" @click="closeSession">Close session</button>
            </div>
            <div ref="termEl" class="term-host"></div>
          </div>
          <div class="card" v-else-if="sessionReplay">
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
          <p class="page-sub">Host file browser (M2). Reads are open to viewers; upload / edit / perm are policy-gated (<span class="mono">file.write</span> / <span class="mono">file.perm</span>) and audited. Edits are compare-and-swap — a save aborts if the file changed since you opened it.</p>
          <div v-if="fileHost && fileRoot" class="info-box"><b>File root:</b> <span class="mono">{{ fileRoot }}</span> — every path below is relative to this directory. The no-escape invariant: no role or parameter can reach outside the root through the file surface.</div>
          <div v-else-if="fileHost" class="warn-box"><b>Legacy agent:</b> no file root reported — the file surface on this host is not confined to a root (pre file-root agent). Upgrade the agent; with <span class="mono">PARTOUT_REQUIRE_FILE_ROOT</span> set, file ops to this host are refused.</div>
          <div class="toolbar">
            <select :value="fileHost" style="max-width:260px" @change="pickFileHost($event.target.value)">
              <option v-for="h in hosts" :key="h.id" :value="h.id">{{ hostOption(h) }}</option>
            </select>
            <input v-model="fileDir" class="mono" style="flex:1" @keyup.enter="listFiles" />
            <button class="btn sm" @click="fileUp">↑</button>
            <button class="btn sm" @click="listFiles">Open</button>
            <button class="btn primary sm" :disabled="!isOperator || !fileHost" @click="openUpDlg()" title="Ship a local file to the host (policy-gated file.write)">+ Upload</button>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Name</th><th>Size</th><th>Mode</th><th>Modified</th><th></th></tr></thead>
              <tbody>
                <tr v-for="(f,i) in fileEntries" :key="i">
                  <td class="mono" :style="{cursor: f.is_dir?'pointer':'default'}" @click="openFile(f)">{{ f.is_dir ? '📁' : (f.is_symlink ? '🔗' : '📄') }} {{ f.name }}</td>
                  <td class="mono">{{ f.is_dir ? '—' : fmtBytes(f.size) }}</td>
                  <td class="mono">{{ f.mode || '—' }}</td>
                  <td class="muted">{{ fmtAgo(f.mtime_unix) }}</td>
                  <td class="row-actions"><button v-if="!f.is_dir && !f.is_symlink" class="btn sm" @click.stop="openFileDlg(f)">Edit</button><button v-if="!f.is_dir && !f.is_symlink" class="btn sm" :disabled="!fileHost" @click="downloadFile(f)">Download</button></td>
                </tr>
                <tr v-if="!fileLoading && !fileEntries.length"><td colspan="5"><div class="empty">{{ fileHost ? 'Empty or no access.' : 'No hosts available.' }}</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ JOBS ============ -->
        <section v-else-if="page==='jobs'">
          <h1 class="page">Jobs</h1>
          <p class="page-sub">Scheduled jobs (M3). Create/update are policy-gated: the task's steps are evaluated under <span class="mono">task.run</span> per host before saving (a deny → 403, nothing written).</p>
          <div class="card">
            <div class="head">
              <h2>Jobs</h2>
              <div class="spacer"></div>
              <button class="btn primary sm" :disabled="!isOperator" @click="newJobForm()">+ New job</button>
            </div>
            <table class="tbl">
              <thead><tr><th>ID</th><th>Name</th><th>Task</th><th>Schedule</th><th>Selector</th><th>Enabled</th><th></th></tr></thead>
              <tbody>
                <template v-for="j in jobs" :key="j.id">
                <tr>
                  <td class="mono">{{ j.id }}</td>
                  <td>{{ j.name }}</td>
                  <td class="mono">{{ j.task_id }}<template v-if="j.task_version">@{{ j.task_version }}</template></td>
                  <td class="mono">{{ j.cron }}</td>
                  <td class="mono">{{ j.selector }}</td>
                  <td>{{ j.enabled ? 'yes' : 'no' }}</td>
                  <td style="white-space:nowrap">
                    <button class="btn sm" :disabled="!isOperator || jobRunBusy===j.id" @click="runJob(j)"><span v-if="jobRunBusy===j.id" class="spin"></span>Run now</button>
                    <button class="btn sm" :disabled="!isOperator" @click="editJob(j)">Edit</button>
                    <button class="btn sm" :disabled="!isOperator" @click="showJobRuns(j.id)">Runs</button>
                    <button class="btn danger sm" :disabled="!isOperator" @click="deleteJob(j)">Delete</button>
                  </td>
                </tr>
                <tr v-if="jobNote[j.id]" class="row-note">
                  <td colspan="7"><div class="prov-inline">
                    <span v-if="jobNote[j.id].kind==='err'" class="err-box" style="margin:0">{{ jobNote[j.id].text }}</span>
                    <span v-else class="muted small">{{ jobNote[j.id].text }}</span>
                    <button class="btn sm" style="margin-left:8px" @click="dismissNote(jobNote, j.id)">Dismiss</button>
                  </div></td>
                </tr>
                </template>
                <tr v-if="!jobs.length && !pageLoading"><td colspan="7"><div class="empty"><div class="big">▦</div>No jobs.<div style="margin-top:10px"><button class="btn primary sm" :disabled="!isOperator" @click="newJobForm()">+ New job</button></div></div></td></tr>
              </tbody>
            </table>

            <div v-if="jobForm" class="card" style="background:var(--brand-subtle);margin-top:12px">
              <h2>{{ jobForm.id ? 'Edit job' : 'New job' }}</h2>
              <div class="grid cols-2">
                <label class="fld"><span>Name</span><input v-model="jobForm.name" /></label>
                <label class="fld"><span>Task</span>
                  <select v-model="jobForm.task_id">
                    <option value="" v-if="!tasks.length">no tasks (create one on the Tasks page)</option>
                    <option v-for="t in tasks" :key="t.id" :value="t.id">{{ t.name }} ({{ t.id }})</option>
                  </select>
                </label>
                <label class="fld"><span>Cron</span><input v-model="jobForm.cron" class="mono" placeholder="0 3 * * *" /></label>
                <label class="fld"><span>Selector</span><input v-model="jobForm.selector" class="mono" placeholder="all | role:db | host:ag_x" /></label>
              </div>
              <div class="toolbar" style="margin-top:10px">
                <label class="lbl" style="margin:0"><input type="checkbox" v-model="jobForm.enabled" /> enabled</label>
                <div class="spacer"></div>
                <button class="btn sm" @click="jobForm=null">Cancel</button>
                <button class="btn primary sm" :disabled="!jobForm.name || !jobForm.cron || !jobForm.task_id || !jobForm.selector || !!jobBusy" @click="saveJob()">
                  <span v-if="jobBusy" class="spin"></span>{{ jobForm.id ? 'Save' : 'Create' }}
                </button>
              </div>
              <div v-if="jobErr" class="err-box" style="margin-top:8px">{{ jobErr }}</div>
            </div>

            <template v-if="jobRunsDetail">
              <div class="toolbar" style="margin-top:12px">
                <span class="muted mono small">runs for {{ jobRunsDetail.job_id }}</span>
                <div class="spacer"></div>
                <button class="btn sm" @click="jobRunsDetail=null">Close</button>
              </div>
              <table class="tbl" style="margin-top:8px">
                <thead><tr><th>ID</th><th>Host</th><th>State</th><th>Trigger</th><th>Scheduled</th><th>Error</th></tr></thead>
                <tbody>
                  <tr v-for="r in jobRunsDetail.runs" :key="r.id">
                    <td class="mono">{{ r.id }}</td>
                    <td class="mono">{{ hostNameById(r.agent_id) }}</td>
                    <td><span class="badge" :class="runBadge(r.state)">{{ r.state }}</span></td>
                    <td class="mono">{{ r.trigger || '—' }}</td>
                    <td class="muted">{{ r.scheduled_at ? new Date(r.scheduled_at*1000).toLocaleString() : '—' }}</td>
                    <td class="muted small" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">{{ r.error || '' }}</td>
                  </tr>
                  <tr v-if="!(jobRunsDetail.runs||[]).length"><td colspan="6" class="muted">No runs yet.</td></tr>
                </tbody>
              </table>
            </template>
          </div>
        </section>

        <!-- ============ TASKS ============ -->
        <section v-else-if="page==='tasks'">
          <h1 class="page">Tasks &amp; Playbooks</h1>
          <p class="page-sub">Multi-step automation (M3). Runs are policy-gated (task.run) and can park on approvals.</p>
          <div v-if="taskMsg" class="info-box" style="margin-bottom:12px">{{ taskMsg }}</div>
          <div class="card" style="margin-bottom:12px">
            <div class="head">
              <h2 v-if="!taskFormOpen">New task</h2>
              <button v-if="!taskFormOpen" class="btn sm" :disabled="!isOperator" @click="openTaskForm">Create…</button>
              <template v-else>
                <h2>Create task</h2>
                <button class="btn sm" @click="taskFormOpen=false">Close</button>
              </template>
            </div>
            <template v-if="taskFormOpen">
              <div class="form-row" style="margin:10px 0">
                <label class="fld"><span>Name</span><input v-model="taskForm.name" placeholder="install-haproxy" /></label>
                <label class="fld" style="flex:1"><span>Description</span><input v-model="taskForm.description" placeholder="optional" /></label>
              </div>
              <p class="cap">Steps run in order on the target host.</p>
              <div v-for="(s,i) in taskForm.steps" :key="i" class="step-edit" style="margin-bottom:8px">
                <div class="form-row" style="align-items:flex-end">
                  <label class="fld" style="min-width:120px"><span>Kind</span><select v-model="s.kind"><option>command</option><option>file</option><option>package</option><option>service</option></select></label>
                  <label class="fld" style="flex:1"><span>Name (display)</span><input v-model="s.name" placeholder="optional" /></label>
                  <button class="btn danger sm" @click="taskForm.steps.splice(i,1)">Remove</button>
                </div>
                <div class="form-row" v-if="s.kind==='command'">
                  <label class="fld" style="flex:2"><span>Command</span><input v-model="s.command" class="mono" placeholder="/usr/sbin/haproxy" /></label>
                  <label class="fld" style="flex:3"><span>Args (space-separated)</span><input v-model="s.args" class="mono" placeholder="-f /etc/haproxy.cfg" /></label>
                </div>
                <div class="form-row" v-if="s.kind==='file'">
                  <label class="fld" style="flex:1"><span>Path</span><input v-model="s.path" class="mono" placeholder="/etc/haproxy.cfg" /></label>
                  <label class="fld" style="flex:2"><span>Content</span><input v-model="s.content" class="mono" placeholder="file content" /></label>
                  <label class="fld" style="min-width:90px"><span>Mode</span><input v-model="s.mode" class="mono" placeholder="0644" /></label>
                </div>
                <div class="form-row" v-if="s.kind==='package'">
                  <label class="fld" style="flex:1"><span>Package</span><input v-model="s.package" class="mono" placeholder="haproxy" /></label>
                  <label class="fld" style="min-width:110px"><span>State</span><select v-model="s.state"><option>installed</option><option>absent</option></select></label>
                </div>
                <div class="form-row" v-if="s.kind==='service'">
                  <label class="fld" style="flex:1"><span>Service</span><input v-model="s.service" class="mono" placeholder="haproxy" /></label>
                  <label class="fld" style="min-width:110px"><span>State</span><select v-model="s.state"><option>running</option><option>stopped</option></select></label>
                </div>
              </div>
              <div class="form-row">
                <button class="btn sm" @click="addTaskStep">+ Add step</button>
                <button class="btn primary sm" :disabled="!taskForm.name || !taskForm.steps.length || taskCreateBusy" @click="saveTask">Create task</button>
              </div>
            </template>
            <p v-else class="muted" style="margin:0">Define a versioned, multi-step automation to run on hosts (via a playbook or Run…).</p>
          </div>
          <div class="grid cols-2">
            <div class="card">
              <h2>Tasks</h2><p class="cap">Versioned step lists</p>
              <table class="tbl"><thead><tr><th>ID</th><th>Name</th><th>Description</th><th></th></tr></thead>
                <tbody>
                  <template v-for="t in tasks" :key="t.id">
                  <tr>
                    <td class="mono">{{ t.id }}</td><td>{{ t.name }}</td><td class="muted">{{ t.description || '—' }}</td>
                    <td><button class="btn sm" :disabled="!isOperator || taskBusy===t.id" @click="runTask(t)"><span v-if="taskBusy===t.id" class="spin"></span>Run…</button></td>
                  </tr>
                  <tr v-if="taskNote[t.id]" class="row-note">
                    <td colspan="4"><div class="prov-inline">
                      <span v-if="taskNote[t.id].kind==='err'" class="err-box" style="margin:0">{{ taskNote[t.id].text }}</span>
                      <span v-else class="muted small">{{ taskNote[t.id].text }}</span>
                      <button class="btn sm" style="margin-left:8px" @click="dismissNote(taskNote, t.id)">Dismiss</button>
                    </div></td>
                  </tr>
                  </template>
                  <tr v-if="!tasks.length && !pageLoading"><td colspan="4"><div class="empty"><div class="big">▦</div>No tasks.<div style="margin-top:10px"><button class="btn sm" :disabled="!isOperator" @click="openTaskForm()">Create task</button></div></div></td></tr>
                </tbody>
              </table>
            </div>
            <div class="card">
              <h2>Playbooks</h2><p class="cap">Task + selector, fan-out run</p>
              <table class="tbl"><thead><tr><th>ID</th><th>Name</th><th>Task</th><th>Selector</th><th></th></tr></thead>
                <tbody>
                  <template v-for="p in playbooks" :key="p.id">
                  <tr>
                    <td class="mono">{{ p.id }}</td><td>{{ p.name }}</td>
                    <td class="mono">{{ p.task_id }}<template v-if="p.task_version">@{{ p.task_version }}</template></td>
                    <td class="mono">{{ p.selector || '—' }}</td>
                    <td><button class="btn sm" :disabled="!isOperator || taskBusy===p.id" @click="runPlaybook(p)"><span v-if="taskBusy===p.id" class="spin"></span>Run</button></td>
                  </tr>
                  <tr v-if="taskNote[p.id]" class="row-note">
                    <td colspan="5"><div class="prov-inline">
                      <span v-if="taskNote[p.id].kind==='err'" class="err-box" style="margin:0">{{ taskNote[p.id].text }}</span>
                      <span v-else class="muted small">{{ taskNote[p.id].text }}</span>
                      <button class="btn sm" style="margin-left:8px" @click="dismissNote(taskNote, p.id)">Dismiss</button>
                    </div></td>
                  </tr>
                  </template>
                  <tr v-if="!playbooks.length && !pageLoading"><td colspan="5"><div class="empty">No playbooks.</div></td></tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="card" style="margin-top:12px">
            <div class="head"><h2>Recent task runs</h2><div class="spacer"></div><button class="btn sm" @click="loadTaskRuns">Refresh</button></div>
            <table class="tbl">
              <thead><tr><th>ID</th><th>Task</th><th>Host</th><th>State</th><th>Started</th><th></th></tr></thead>
              <tbody>
                <tr v-for="r in taskRuns" :key="r.id" class="click" @click="showTaskRun(r.id)">
                  <td class="mono">{{ r.id }}</td>
                  <td class="mono">{{ r.task_id }}<template v-if="r.task_version">@{{ r.task_version }}</template></td>
                  <td class="mono">{{ hostNameById(r.agent_id) }}</td>
                  <td><span class="badge" :class="taskRunBadge(r.state)">{{ r.state }}</span></td>
                  <td class="muted">{{ r.started ? new Date(r.started*1000).toLocaleString() : '—' }}</td>
                  <td class="muted small">{{ taskRunDetail && taskRunDetail.id===r.id ? 'hide ▴' : 'steps ▸' }}</td>
                </tr>
                <tr v-if="!taskRuns.length"><td colspan="6"><div class="empty">No task runs.</div></td></tr>
              </tbody>
            </table>
            <template v-if="taskRunDetail">
              <div class="toolbar" style="margin-top:8px">
                <span class="muted mono small">run {{ taskRunDetail.id }} · {{ hostNameById(taskRunDetail.agent_id) }}</span>
                <span class="muted small" v-if="taskRunDetail.error">{{ taskRunDetail.error }}</span>
                <div class="spacer"></div>
                <button class="btn sm" @click="taskRunDetail=null">Close</button>
              </div>
              <table class="tbl" v-if="(taskRunDetail.steps||[]).length" style="margin-top:8px">
                <thead><tr><th>#</th><th>Kind</th><th>Step</th><th>State</th><th>Detail</th></tr></thead>
                <tbody>
                  <tr v-for="s in taskRunDetail.steps" :key="s.index">
                    <td class="mono">{{ s.index }}</td><td class="mono">{{ s.kind }}</td>
                    <td class="mono">{{ s.name || '—' }}</td>
                    <td><span class="badge" :class="stepBadge(s.state)">{{ s.state }}</span></td>
                    <td class="mono small" style="max-width:380px;overflow:hidden;text-overflow:ellipsis">{{ s.detail || '—' }}</td>
                  </tr>
                </tbody>
              </table>
            </template>
          </div>
        </section>

        <!-- ============ UPDATES ============ -->
        <section v-else-if="page==='updates'">
          <h1 class="page">Updates</h1>
          <div class="tabs">
            <div class="tab" :class="{active: updTab==='packages'}" @click="updTab='packages'">Packages</div>
            <div class="tab" :class="{active: updTab==='releases'}" @click="updTab='releases'; loadReleases()">Releases</div>
            <div class="tab" :class="{active: updTab==='runs'}" @click="updTab='runs'; loadRuns()">Runs</div>
          </div>
          <template v-if="updTab==='packages'">
          <p class="page-sub">Package updates for the selected host (M3). Apply is policy-gated (pkg.apply) and can park on approvals; the agent always runs a dry-run first.</p>
          <div class="toolbar">
            <select :value="updHost" style="max-width:260px" @change="updHost=$event.target.value; loadUpdates()">
              <option v-for="h in hosts" :key="h.id" :value="h.id">{{ hostOption(h) }}</option>
            </select>
            <button class="btn sm" @click="loadUpdates">Refresh</button>
            <span class="ext-status" :class="{ 'ext-err': extStatus && extStatus.last_error, 'ext-stale': extStatus && !extStatus.last_error && (Date.now()/1000 - (extStatus.last_at||0) > 86400) }" :data-tip="extStatus ? 'last refresh: ' + (extStatus.last_at ? new Date(extStatus.last_at*1000).toLocaleString() : 'never') + (extStatus.last_error ? ' — ' + extStatus.last_error : '') : 'unknown'">
              EOL data: {{ extStatus ? (extStatus.last_at ? 'updated ' + fmtAgo(extStatus.last_at) : 'never') : '…' }}{{ extStatus && extStatus.last_error ? ' ⚠' : '' }}
            </span>
            <button v-if="isAdmin" class="btn sm" :disabled="!!extBusy" @click="refreshExtData"><span v-if="extBusy" class="spin"></span> Refresh EOL data</button>
            <div class="spacer"></div>
            <button class="btn sm" :disabled="!updates.length" @click="setPkgChecks(updates.map(u=>u.name))" title="Check every pending update">Sel. all</button>
            <button class="btn sm" :disabled="!updates.length" @click="setPkgChecks(updates.filter(u=>u.is_security).map(u=>u.name))" title="Check only the updates flagged security">Sel. security</button>
            <input v-model="pkgSel" class="mono" placeholder="or type packages (blank = all; checked rows win)" style="flex:1;max-width:340px" />
            <label class="lbl" style="margin:0;display:flex;align-items:center;gap:4px"><input type="checkbox" v-model="pkgDryRun" /> dry run</label>
            <button class="btn primary sm" :disabled="!isOperator || !updHost || !!pkgBusy" @click="applyUpdates">
              <span v-if="pkgBusy" class="spin"></span> Apply
            </button>
          </div>
          <div v-if="pkgMsg" class="info-box" style="margin-bottom:12px">{{ pkgMsg }}</div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th style="width:30px" title="Select all pending updates"><input type="checkbox" :checked="updates.length>0 && updates.every(u=>pkgChecked[u.name])" @change="setPkgChecks($event.target.checked ? updates.map(u=>u.name) : [])" /></th><th>Package</th><th>Installed</th><th>Available</th><th>Vulns</th></tr></thead>
              <tbody>
                <tr v-for="(u,i) in updates" :key="u.name || i">
                  <td><input type="checkbox" :checked="!!pkgChecked[u.name]" @change="togglePkgCheck(u.name, $event.target.checked)" :aria-label="'select ' + u.name" /></td>
                  <td class="mono">{{ u.name }}</td>
                  <td class="mono">{{ u.installed || '—' }}</td>
                  <td class="mono">{{ u.available || '—' }}</td>
                  <td>
                    <span v-if="u.is_security" class="badge bad">security</span>
                    <span v-if="u.vuln_count" class="badge" :class="u.max_severity==='critical'?'bad':(u.max_severity==='high'?'warn':'neutral')">{{ u.vuln_count }} · {{ u.max_severity }}</span>
                    <span v-if="!u.is_security && !u.vuln_count" class="muted">—</span>
                  </td>
                </tr>
                <tr v-if="!updates.length"><td colspan="5"><div class="empty">No pending updates (or no host selected).</div></td></tr>
              </tbody>
            </table>
          </div>
          <div class="card" style="margin-top:12px">
            <div class="head"><h2>Package actions</h2><div class="spacer"></div><button class="btn sm" @click="loadPkgActions">Refresh</button></div>
            <table class="tbl">
              <thead><tr><th>ID</th><th>Host</th><th>Kind</th><th>Status</th><th>Applied</th><th>When</th><th></th></tr></thead>
              <tbody>
                <tr v-for="a in pkgActions" :key="a.id" class="click" @click="showPkgAction(a.id)">
                  <td class="mono">{{ a.id }}</td>
                  <td class="mono">{{ hostNameById(a.agent_id) }}</td>
                  <td class="mono">{{ a.kind }}</td>
                  <td><span class="badge" :class="pkgActionBadge(a.status)">{{ a.status }}</span></td>
                  <td class="mono">{{ a.applied_count || '—' }}</td>
                  <td class="muted">{{ fmtAgo(a.created) }}</td>
                  <td class="muted small">{{ pkgActionDetail && pkgActionDetail.id===a.id ? 'hide ▴' : 'summary ▸' }}</td>
                </tr>
                <tr v-if="!pkgActions.length && !pageLoading"><td colspan="7"><div class="empty">No package actions.</div></td></tr>
              </tbody>
            </table>
            <div v-if="pkgActionDetail" class="console" style="margin-top:8px;max-height:220px;white-space:pre-wrap">{{ pkgActionDetail.dry_summary || pkgActionDetail.error || '(no summary)' }}</div>
          </div>
          <div class="card" style="margin-top:12px">
            <div class="head"><h2>Security — unpatched CVEs (fleet)</h2><div class="spacer"></div>
              <span class="muted small">server-side scan: per-host update list + OSV correlation (M5.1)</span>
              <button v-if="isAdmin" class="btn sm" :disabled="!!secBusy" @click="scanSecurity"><span v-if="secBusy" class="spin"></span> Scan now</button>
              <button v-if="isOperator" class="btn primary sm" :disabled="!!secPatchBusy || !secPatchTargets().length" :data-tip="'Patch the CVE-affected packages on every host with findings (dry-run first, policy-gated)'" @click="patchAllSecurity"><span v-if="secPatchBusy" class="spin"></span> Patch all security</button>
            </div>
            <table class="tbl">
              <thead><tr><th>Host</th><th>Last scan</th><th>Updates</th><th>Security</th><th>Top findings (patchable via Apply above)</th><th></th></tr></thead>
              <tbody>
                <tr v-for="s in security" :key="s.agent_id">
                  <td class="mono">{{ hostNameById(s.agent_id) }}</td>
                  <td class="muted">{{ fmtAgo(s.scanned_at) }}</td>
                  <td class="muted">{{ s.updates_total }}</td>
                  <td>
                    <span v-if="s.security_updates" class="badge" :class="secCountBadge(s)">{{ s.security_updates }}</span>
                    <span v-else class="muted">—</span>
                  </td>
                  <td>
                    <div v-for="f in (s.findings || []).slice(0, 3)" :key="f.pkg" class="small">
                      <span class="mono">{{ f.pkg }}</span>
                      <span class="muted mono">{{ f.installed }}→{{ f.available }}</span>
                      <span v-if="f.vuln_ids" class="mono muted">{{ f.vuln_ids.split(',')[0] }}</span>
                      <span v-if="f.vuln_count > 1" class="muted">+{{ f.vuln_count - 1 }}</span>
                    </div>
                    <span v-if="!(s.findings || []).length" class="muted">no known CVEs on installed packages</span>
                  </td>
                  <td style="white-space:nowrap"><button v-if="(s.findings || []).length && isOperator" class="btn ok sm" :data-tip="'Patch ' + (s.findings || []).length + ' CVE-affected package(s) on this host'" @click="patchHostSecurity(s)">Patch</button></td>
                </tr>
                <tr v-if="!security.length && !pageLoading"><td colspan="6"><div class="empty">No host scanned yet — the scan runs automatically (PARTOUT_SECURITY_SCAN_S, default 6 h) or press “Scan now”.</div></td></tr>
              </tbody>
            </table>
          </div>
          </template>
          <template v-else-if="updTab==='releases'">
            <p class="page-sub">Partout release artifacts (M8.1). The server stores and serves them; each agent verifies the Ed25519 signature against its own release public key before executing anything. <b>Beta:</b> releases without a signature are accepted while unsigned updates are enabled (<span class="mono">PARTOUT_ALLOW_UNSIGNED_RELEASES</span>, default on) — keyless agents apply them on the sha256 integrity check alone; a provisioned release key stays strict-signed. Upload requires admin; downloading the artifact requires operator.</p>
            <div class="card">
              <div class="head"><h2>Releases</h2><div class="spacer"></div><button class="btn sm" @click="loadReleases">Refresh</button></div>
              <table class="tbl">
                <thead><tr><th>Version</th><th>Arch</th><th>Kind</th><th>SHA256</th><th>Trust</th><th>Size</th><th>Uploaded</th><th>By</th><th></th></tr></thead>
                <tbody>
                  <tr v-for="r in releases" :key="r.id">
                    <td class="mono">{{ r.version }}</td>
                    <td class="mono">{{ r.arch }}</td>
                    <td>{{ r.kind }}</td>
                    <td class="mono" tabindex="0" :data-jtip="r.sha256 || ''">{{ (r.sha256 || '').slice(0, 12) }}…</td>
                    <td><span v-if="r.signature" class="badge ok">signed</span><span v-else class="badge warn" data-tip="no signature — only keyless agents apply it, and only while the server allows unsigned releases (PARTOUT_ALLOW_UNSIGNED_RELEASES=true)">unsigned</span></td>
                    <td class="muted">{{ fmtBytes(r.size) }}</td>
                    <td class="muted">{{ fmtAgo(r.created) }}</td>
                    <td class="muted">{{ r.uploaded_by || '—' }}</td>
                    <td class="row-actions"><button class="btn danger sm" :disabled="!isAdmin" @click="deleteRelease(r)">Delete</button></td>
                  </tr>
                  <tr v-if="!releases.length && !pageLoading"><td colspan="9"><div class="empty">No releases uploaded yet (<span class="mono">partout ctl update upload …</span>).</div></td></tr>
                </tbody>
              </table>
            </div>
            <div class="card" style="margin-top:12px">
              <div class="head"><h2>Upload a release</h2></div>
              <div class="form-row" style="align-items:flex-end">
                <label class="fld"><span>Version</span><input v-model="relForm.version" class="mono" placeholder="v0.9.0" /></label>
                <label class="fld"><span>Arch</span><input v-model="relForm.arch" class="mono" placeholder="linux-amd64" /></label>
                <label class="fld"><span>Kind</span><select v-model="relForm.kind"><option value="agent">agent</option><option value="server">server</option></select></label>
                <label class="fld" style="flex:1"><span>Signature (base64, 64-byte Ed25519)</span><input v-model="relForm.signature" class="mono" placeholder="required unless the server allows unsigned (PARTOUT_ALLOW_UNSIGNED_RELEASES=true)" /></label>
                <label class="fld"><span>Artifact</span><input type="file" @change="onRelFile" /></label>
                <button class="btn primary" :disabled="!isAdmin || !relForm.version || !relForm.arch || !relForm.file || relBusy" @click="uploadRelease"><span v-if="relBusy" class="spin"></span> Upload</button>
              </div>
              <p class="muted small" style="margin-top:8px">Sign locally first: <span class="mono">partout ctl update sign --version … --arch … --kind … --file …</span>. The server stores the signature as-is and checks the artifact sha256 (declared, or computed from the bytes). <b>Beta:</b> an empty signature uploads an <i>unsigned</i> release (allowed while <span class="mono">PARTOUT_ALLOW_UNSIGNED_RELEASES</span> is on); keyless agents apply it on the sha256 check alone.</p>
            </div>
          </template>
          <template v-else-if="updTab==='runs'">
            <p class="page-sub">Fleet rollouts (M8.1): canary, then waves of the resolved selector. The server dispatches signed directives; each agent verifies the release signature before swapping its binary, and rolls back to N-1 automatically on failure. <span class="mono">partout ctl update run …</span> does the same.</p>
            <div class="card">
              <div class="head"><h2>New rollout</h2><div class="spacer"></div><button class="btn sm" @click="loadRuns">Refresh runs</button></div>
              <div class="form-row" style="align-items:flex-end">
                <label class="fld" style="flex:1"><span>Release</span><select v-model="runForm.release_id"><option value="" disabled>choose…</option><option v-for="r in releases.filter(x => x.kind==='agent')" :key="r.id" :value="r.id">{{ r.version }} ({{ r.arch }})</option></select></label>
                <label class="fld" style="flex:1"><span>Selector</span><input v-model="runForm.selector" class="mono" placeholder="all" /></label>
                <label class="fld"><span>Canary</span><input v-model.number="runForm.canary" type="number" min="0" style="width:70px" /></label>
                <label class="fld"><span>Wave %</span><input v-model.number="runForm.wave" type="number" min="1" max="100" style="width:70px" /></label>
                <button class="btn primary" :disabled="!isAdmin || !runForm.release_id || !runForm.selector || runBusy" @click="createRun"><span v-if="runBusy" class="spin"></span> Start run</button>
              </div>
              <p v-if="runNotice" class="muted small" style="margin-top:8px">{{ runNotice }}</p>
            </div>
            <div class="card" style="margin-top:12px">
              <div class="head"><h2>Runs</h2></div>
              <table class="tbl">
                <thead><tr><th>Version</th><th>Selector</th><th>Status</th><th>Wave</th><th>Done</th><th>Failed</th><th>Skipped</th><th>Total</th><th>Created</th><th></th></tr></thead>
                <tbody>
                  <tr v-for="r in runs" :key="r.id" style="cursor:pointer" @click="openRun(r.id)">
                    <td class="mono">{{ r.version }}</td>
                    <td class="mono">{{ r.selector }}</td>
                    <td><span class="badge" :class="runStatusKind(r.status)">{{ r.status }}</span></td>
                    <td class="muted">{{ r.current_wave }}</td>
                    <td class="muted">{{ r.done_hosts }}</td>
                    <td class="muted" :style="r.failed_hosts ? 'color:#d66' : ''">{{ r.failed_hosts }}</td>
                    <td class="muted">{{ r.skipped_hosts }}</td>
                    <td class="muted">{{ r.total_hosts }}</td>
                    <td class="muted">{{ fmtAgo(r.created) }}</td>
                    <td class="row-actions"><button v-if="r.status==='draft'" class="btn primary sm" :disabled="!isAdmin" @click.stop="startDraft(r.id)">Start</button> <button class="btn sm" @click.stop="openRun(r.id)">Detail</button></td>
                  </tr>
                  <tr v-if="!runs.length && !pageLoading"><td colspan="10"><div class="empty">No rollout runs yet.</div></td></tr>
                </tbody>
              </table>
            </div>
            <div v-if="runDetail" class="card" style="margin-top:12px">
              <div class="head"><h2>Run {{ runDetail.run.id }} — {{ runDetail.run.version }}</h2><div class="spacer"></div>
                <button v-if="runDetail.run.status==='draft'" class="btn primary sm" :disabled="!isAdmin || runBusy" @click="runAction('start')">Start rollout</button>
                <button v-if="runDetail.run.status==='paused_failure'" class="btn sm" :disabled="!isAdmin || runBusy" @click="runAction('retry')">Retry failed</button>
                <button v-if="runDetail.run.status==='paused_failure'" class="btn sm" :disabled="!isAdmin || runBusy" @click="runAction('skip')">Skip failed</button>
                <button v-if="!runTerminal(runDetail.run.status)" class="btn danger sm" :disabled="!isAdmin || runBusy" @click="runAction('abort')">Abort</button>
              </div>
              <table class="tbl">
                <thead><tr><th>Host</th><th>Status</th><th>Version</th><th>Error</th></tr></thead>
                <tbody>
                  <tr v-for="h in runDetail.hosts" :key="h.id">
                    <td><div class="hostcell"><span>{{ hostNameById(h.host_id) }}</span><span class="hostid mono">{{ h.host_id }}</span></div></td>
                    <td><span class="badge" :class="runStatusKind(h.status)">{{ h.status }}</span></td>
                    <td class="mono muted">{{ h.version || '—' }}</td>
                    <td class="muted" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" tabindex="0" :data-jtip="h.error || ''">{{ h.error || '' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>
        </section>

        <!-- ============ SECRETS ============ -->
        <section v-else-if="page==='secrets'">
          <h1 class="page">Secrets</h1>
          <p class="page-sub">Encrypted at rest; values are write-only and never displayed (ui-guidelines §12.6).</p>
          <div class="card" style="margin-bottom:12px">
            <div class="form-row" style="align-items:flex-end">
              <label class="fld"><span>Name</span><input v-model="secretForm.name" class="mono" placeholder="db-password" /></label>
              <label class="fld" style="flex:1"><span>Value</span><input v-model="secretForm.value" type="password" placeholder="secret value" /></label>
              <label class="fld"><span>Selector</span><input v-model="secretForm.selector" placeholder="all" /></label>
              <button class="btn primary" :disabled="!isAdmin || !secretForm.name || !secretForm.value || secretBusy" @click="createSecret">Create secret</button>
            </div>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Name</th><th>Selector</th><th>Version</th><th></th></tr></thead>
              <tbody>
                <tr v-for="s in secrets" :key="s.name">
                  <td class="mono">{{ s.name }}</td>
                  <td class="mono">{{ s.selector || 'all' }}</td>
                  <td class="muted">v{{ s.version || 0 }}</td>
                  <td class="row-actions">
                    <button class="btn sm" :disabled="!isAdmin" @click="rotateSecret(s.name)">Rotate</button>
                    <button class="btn danger sm" :disabled="!isAdmin" @click="deleteSecret(s.name)">Delete</button>
                  </td>
                </tr>
                <tr v-if="!secrets.length && !pageLoading"><td colspan="4"><div class="empty">No secrets (or feature disabled).</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ POLICIES ============ -->
        <section v-else-if="page==='policies'">
          <h1 class="page">Policies</h1>
          <p class="page-sub">Command policy rules (PRD R7).</p>
          <div class="card" v-if="presetStatus" style="margin-bottom:12px">
            <div class="toolbar">
              <div><strong>Fleet defaults (preset)</strong>
                <span class="muted"> — the safety-net rules seeded on first boot; every <span class="mono">default-*</span> row can be edited or deleted.</span></div>
              <button class="btn sm" v-if="presetMissing > 0 && isAdmin" @click="applyPreset">Apply missing ({{ presetMissing }})</button>
            </div>
            <div v-if="presetMissing > 0" class="muted" style="margin-top:6px">Missing: {{ presetMissingList }}</div>
          </div>
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
                <tr v-if="!policies.length && !pageLoading"><td colspan="6"><div class="empty">No policies.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ APPROVALS ============ -->
        <section v-else-if="page==='approvals'">
          <h1 class="page">Approvals</h1>
          <p class="page-sub">Actions parked by <span class="mono">require_approval</span> policy rules — scoped to the exact payload (M4, PRD §5.8). Deciding requires the admin role.</p>
          <div class="card">
            <div class="toolbar" style="margin-bottom:8px">
              <label class="lbl">State</label>
              <select v-model="apprState" @change="loadApprovals">
                <option value="pending">pending</option>
                <option value="approved">approved</option>
                <option value="denied">denied</option>
                <option value="expired">expired</option>
                <option value="">all</option>
              </select>
              <button class="btn sm" @click="loadApprovals">Refresh</button>
              <span v-if="apprMsg" style="color:var(--bad,#b00)">{{ apprMsg }}</span>
            </div>
            <table class="tbl">
              <thead><tr><th>ID</th><th>Class</th><th>Agent</th><th>Actor</th><th>Matched rules</th><th>Created</th><th>Expires</th><th>State</th><th>Decision</th><th></th></tr></thead>
              <tbody>
                <tr v-for="a in approvals" :key="a.id">
                  <td class="mono">{{ a.id }}</td>
                  <td class="mono">{{ a.action_class }}</td>
                  <td class="mono">{{ hostNameById(a.agent_id) }}</td>
                  <td>{{ a.actor || "—" }} <span class="muted" v-if="a.actor_role">({{ a.actor_role }})</span></td>
                  <td><span class="chip" v-for="r in (a.matched_rules||'').split(',').filter(Boolean)" :key="r">{{ r }}</span><span v-if="!(a.matched_rules||'')" class="muted">—</span></td>
                  <td>{{ fmtAgo(a.created_unix) }}</td>
                  <td>{{ fmtDate(a.expires_unix) }}</td>
                  <td><span class="badge" :class="a.state==='approved'?'ok':(a.state==='pending'?'warn':'neutral')">{{ a.state }}</span></td>
                  <td class="muted">{{ a.decided_by ? a.decided_by + (a.decision_reason ? ' — ' + a.decision_reason : '') : '—' }}</td>
                  <td v-if="a.state==='pending' && isAdmin" style="white-space:nowrap">
                    <button class="btn ok sm" :disabled="apprBusy===a.id" @click="decideApproval(a.id,'approve')">Approve</button>
                    <button class="btn danger sm" :disabled="apprBusy===a.id" @click="decideApproval(a.id,'deny')">Deny</button>
                  </td>
                </tr>
                <tr v-if="!approvals.length && !pageLoading"><td colspan="10"><div class="empty">No approval requests{{ apprState ? ' (' + apprState + ')' : '' }}.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ MCP ============ -->
        <section v-else-if="page==='mcp'">
          <h1 class="page">MCP</h1>
          <p class="page-sub">MCP server for AI assistants (R11, PRD §10.3): JSON-RPC 2.0 over stdio + Streamable HTTP. Read tools are read-only; write tools are RBAC- and policy-gated by the same control plane the UI uses.</p>
          <div v-if="!mcpInfo">
            <div class="card"><div class="empty">MCP surface not available in this build.</div></div>
          </div>
          <template v-else>
            <div class="card" style="margin-bottom:12px">
              <h2>Connect</h2>
              <table class="tbl">
                <tbody>
                  <tr><td style="width:170px">HTTP endpoint</td><td class="mono">POST {{ protocolHost() }}{{ mcpInfo.http_endpoint }}</td></tr>
                  <tr><td>Protocol</td><td class="mono">{{ mcpInfo.protocol_version }} (JSON-RPC 2.0)</td></tr>
                  <tr><td>Transports</td><td>{{ mcpInfo.transports.join(' + ') }}</td></tr>
                  <tr><td>Auth</td><td>{{ mcpInfo.auth }}</td></tr>
                </tbody>
              </table>
              <h2 style="margin-top:12px">stdio client config (mcp.json)</h2>
              <p class="cap">Paste into your MCP client (Claude Code / Cursor); replace the token placeholder with a bearer token.</p>
              <pre class="console" style="white-space:pre-wrap">{{ mcpSnippet() }}</pre>
            </div>
            <div class="card" style="margin-bottom:12px">
              <h2>OAuth2 clients ({{ mcpClients.length }})</h2>
              <p class="cap">Registered MCP OAuth2 (PKCE) clients for the HTTP transport. Admins register new clients via <span class="mono">POST /api/v1/mcp/clients</span>.</p>
              <table class="tbl" v-if="mcpClients.length">
                <thead><tr><th>Client</th><th>Name</th><th>Scope</th><th>Created</th></tr></thead>
                <tbody>
                  <tr v-for="c in mcpClients" :key="c.id">
                    <td class="mono">{{ c.id }}</td>
                    <td>{{ c.name }}</td>
                    <td class="muted">{{ c.scope || '—' }}</td>
                    <td class="muted">{{ c.created ? new Date(c.created*1000).toLocaleString() : '—' }}</td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="muted">No MCP clients registered.</p>
            </div>
            <div class="card">
              <h2>Tools ({{ (mcpInfo.tools||[]).length }})</h2>
              <p class="cap">Read tools are read-only; write tools are RBAC- and policy-gated (approvals surface as structured tool errors).</p>
              <table class="tbl">
                <thead><tr><th>Name</th><th>Kind</th><th>Description</th></tr></thead>
                <tbody>
                  <tr v-for="t in (mcpInfo.tools||[])" :key="t.name">
                    <td class="mono" style="white-space:nowrap">{{ t.name }}</td>
                    <td><span class="badge" :class="t.write?'warn':'ok'">{{ t.write?'write':'read' }}</span></td>
                    <td class="muted">{{ t.description }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>
        </section>

        <!-- ============ PROVISION ============ -->
        <section v-else-if="page==='provision'">
          <h1 class="page">Provision</h1>
          <p class="page-sub">Server-initiated host onboarding over the operator's fleet SSH (R17, admin). A new host key pauses the run at <span class="mono">key_confirm</span> until an admin confirms the fingerprint (no silent TOFU).</p>
          <div class="card" style="margin-bottom:12px;display:flex;align-items:center;gap:12px">
            <div style="flex:1">
              <b>Onboard a host (guided)</b>
              <p class="muted small" style="margin:2px 0 0">Step-by-step: pick the target, review the plan, watch the five steps, confirm the host key.</p>
            </div>
            <button class="btn primary" :disabled="!isAdmin" @click="openProvWizard()">Start onboarding →</button>
            <span v-if="!isAdmin" class="muted small">requires admin role</span>
          </div>
          <div class="card" style="margin-bottom:12px">
            <div class="head"><h2>New run</h2><p class="cap">Uses the operator's existing <span class="mono">~/.ssh</span>; no credentials are created or persisted.</p></div>
            <div class="toolbar">
              <input v-model="provHost" class="mono" placeholder="user@host" style="max-width:240px" />
              <select v-model="provMode">
                <option value="fresh" title="fresh: clean slate — stops and removes any existing partout agent + identity on the host, then enrolls a brand-new agent">fresh</option>
                <option value="join" title="join: non-destructive in-place binary update for a host that already has an enrolled agent (identity preserved)">join</option>
              </select>
              <button class="btn primary sm" :disabled="!isAdmin || !provHost || !!provBusy" @click="createProvRun()">Start provisioning</button>
              <span v-if="!isAdmin" class="muted small">requires admin role</span>
            </div>
            <p class="muted small" style="margin-top:8px">{{ provModeHint }}</p>
            <div v-if="provMsg" class="info-box" style="margin-top:8px">{{ provMsg }}</div>
          </div>
          <div class="card">
            <div class="head"><h2>Runs</h2><div class="spacer"></div><button class="btn sm" @click="loadProvRuns">Refresh</button></div>
            <table class="tbl">
              <thead><tr><th>ID</th><th>Host</th><th>Mode</th><th>State</th><th>Key fingerprint</th><th>Started</th><th></th></tr></thead>
              <tbody>
                <template v-for="r in provRuns" :key="r.id">
                <tr class="click" @click="showProvRun(r.id)">
                  <td class="mono">{{ r.id }}</td>
                  <td class="mono">{{ r.host }}</td>
                  <td class="mono">{{ r.mode }}</td>
                  <td><span class="badge" :class="provBadge(r.state).cls">{{ provBadge(r.state).label }}</span><span v-if="r.step && !provTerminal(r.state)" class="muted small"> · {{ r.step }}</span><span v-if="r.error" class="mono small" style="color:var(--critical,#dc2626);display:inline-block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom" tabindex="0" :data-jtip="r.error"> · {{ r.error }}</span></td>
                  <td class="mono small">{{ r.fingerprint || '—' }}</td>
                  <td class="muted" :title="new Date(r.created * 1000).toLocaleString()">{{ fmtAgo(r.created) }}</td>
                  <td style="white-space:nowrap">
                    <template v-if="r.state==='key_confirm' && isAdmin">
                      <button class="btn ok sm" @click.stop="decideProvKey(r.id,'confirm')">Confirm key</button>
                      <button class="btn danger sm" @click.stop="decideProvKey(r.id,'deny')">Deny</button>
                    </template>
                    <button v-if="!provTerminal(r.state)" class="btn sm" @click.stop="provWizWatch(r.id)" title="Open in the onboarding wizard">Watch</button>
                    <button v-if="!provTerminal(r.state) && isAdmin" class="btn danger sm" @click.stop="cancelProvRun(r.id)">Cancel</button>
                    <span v-if="provTerminal(r.state)" style="display:inline-flex;align-items:center;gap:8px">
                      <a v-if="r.agent_id" @click.prevent.stop="go('host/'+r.agent_id)" class="badge" :class="agentBadge((hostMap[r.agent_id]||{}).state).cls" :title="(hostMap[r.agent_id] ? hostName(hostMap[r.agent_id]) : r.agent_id) + ' — open in Fleet'">{{ agentBadge((hostMap[r.agent_id]||{}).state).label }}</a>
                      <span class="muted small">{{ provDetail && provDetail.run && provDetail.run.id===r.id ? 'hide ▴' : 'steps ▸' }}</span>
                    </span>
                  </td>
                </tr>
                <tr v-if="provDetail && provDetail.run && provDetail.run.id===r.id">
                  <td colspan="7"><div class="prov-inline">
                    <div class="toolbar">
                      <span class="muted mono small">run {{ provDetail.run.id }} · {{ provDetail.run.host }} · {{ provDetail.run.state }}</span>
                      <span class="err-box" style="margin:0" v-if="provDetail.run.error">{{ provDetail.run.error }}</span>
                      <template v-if="provDetail.run.agent_id">
                        <span class="badge" :class="agentBadge((hostMap[provDetail.run.agent_id]||{}).state).cls">{{ agentBadge((hostMap[provDetail.run.agent_id]||{}).state).label }}</span>
                        <span class="muted mono small">{{ hostMap[provDetail.run.agent_id] ? hostName(hostMap[provDetail.run.agent_id]) : provDetail.run.agent_id }}</span>
                        <span class="muted small" v-if="hostMap[provDetail.run.agent_id]">last seen {{ fmtAgo(hostMap[provDetail.run.agent_id].last_seen) }}</span>
                        <button class="btn sm" @click="go('host/' + provDetail.run.agent_id)">View host →</button>
                      </template>
                      <div class="spacer"></div>
                      <button class="btn sm" @click="provDetail=null">Close</button>
                    </div>
                    <table class="tbl">
                      <thead><tr><th>#</th><th>Step</th><th>State</th><th>Output excerpt</th></tr></thead>
                      <tbody>
                        <tr v-for="s in provDetail.steps" :key="s.seq">
                          <td class="mono">{{ s.seq }}</td><td class="mono">{{ s.name }}</td>
                          <td><span class="badge" :class="provStepBadge(s.state)">{{ s.state }}</span></td>
                          <td class="mono small" style="max-width:440px;overflow:hidden;text-overflow:ellipsis">{{ s.stderr_excerpt || s.stdout_excerpt || '—' }}</td>
                        </tr>
                        <tr v-if="!(provDetail.steps||[]).length"><td colspan="4" class="muted">No steps recorded yet.</td></tr>
                      </tbody>
                    </table>
                  </div></td>
                </tr>
                </template>
                <tr v-if="!provRuns.length"><td colspan="7"><div class="empty">No provision runs.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ USERS ============ -->
        <section v-else-if="page==='users'">
          <h1 class="page">Users</h1>
          <p class="page-sub">Local identity principals (admin).</p>
          <div class="card" style="margin-bottom:14px">
            <div class="form-row" style="align-items:flex-end">
              <label class="fld"><span>Username</span><input v-model="userForm.username" placeholder="new-admin" /></label>
              <label class="fld"><span>Password</span><input v-model="userForm.password" type="password" placeholder="min 8 chars" /></label>
              <label class="fld"><span>Role</span><select v-model="userForm.role"><option value="admin">admin</option><option value="operator">operator</option><option value="viewer">viewer</option></select></label>
              <button class="btn primary" :disabled="!userForm.username || !userForm.password || userBusy" @click="createUser">Create user</button>
            </div>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Username</th><th>Role</th><th>Status</th><th></th></tr></thead>
              <tbody>
                <tr v-for="u in users" :key="u.username || u.name">
                  <td class="mono">{{ u.username || u.name }}</td>
                  <td>
                    <select class="inline-sel" :value="u.role" @change="setUserRole(u, $event.target.value)"
                      :disabled="(u.username||u.name)===meName">
                      <option value="admin">admin</option><option value="operator">operator</option><option value="viewer">viewer</option>
                    </select>
                  </td>
                  <td><span class="badge" :class="u.disabled?'warn':'ok'">{{ u.disabled ? 'disabled' : 'active' }}</span></td>
                  <td class="row-actions">
                    <button class="btn sm" :disabled="(u.username||u.name)===meName" @click="toggleUserDisabled(u)">{{ u.disabled ? 'Enable' : 'Disable' }}</button>
                    <button class="btn danger sm" :disabled="(u.username||u.name)===meName" @click="deleteUser(u.username||u.name)">Delete</button>
                  </td>
                </tr>
                <tr v-if="!users.length && !pageLoading"><td colspan="4"><div class="empty">No users.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ OBSERVE · SERVICES ============ -->
        <section v-else-if="page==='obs-services'">
          <h1 class="page">Services</h1>
          <p class="page-sub">Fleet service health from agent-collected facts (M5, R18).</p>
          <div class="toolbar">
            <span class="muted small">{{ svcRows.length }} of {{ services.length }} units</span>
            <button v-if="svcFAny" class="btn sm" @click="svcClearF()">Clear filters</button>
            <span class="muted small">· filter on the column headers (filters combine with AND)</span>
          </div>
          <div v-if="svcFAny" class="toolbar" style="background:var(--brand-subtle);border:1px solid var(--border)">
            <span class="muted small">⚡ target:</span>
            <code class="mono">{{ svcTarget }}</code>
            <span class="muted small">({{ svcTargetHint }})</span>
            <button class="btn sm" @click="svcCopySel()">Copy</button>
            <template v-if="isOperator">
              <button class="btn sm" @click="svcNewAlert()">New alert…</button>
              <span class="muted small" style="margin:0 6px">·</span>
              <span class="muted small">save as group:</span>
              <input v-model="svcGroupName" placeholder="group name" class="mono" style="width:110px" @keyup.enter="svcGroupName.trim() && svcSaveGroup()" />
              <button class="btn sm" :disabled="!svcGroupName.trim() || svcGroupBusy" @click="svcSaveGroup()"><span v-if="svcGroupBusy" class="spin"></span>Save group</button>
              <span class="muted small">→ then use <code class="mono">group:&lt;name&gt;</code> as a selector in tasks, jobs &amp; alerts</span>
            </template>
            <span v-else class="muted small">· these filters select hosts; saving a group or alert rule needs the operator role</span>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr>
                <th>Unit<div><input v-model="svcF.unit" placeholder="filter…" style="width:110px;font-size:11px;margin-top:2px" /></div></th>
                <th>Host<div><select v-model="svcF.host" style="font-size:11px;max-width:110px;margin-top:2px"><option value="">all</option><option v-for="h in hosts" :key="h.id" :value="h.id">{{ hostNameById(h.id) }}</option></select></div></th>
                <th>State<div><select v-model="svcF.state" style="font-size:11px;max-width:100px;margin-top:2px"><option value="">all</option><option v-for="v in svcFacets.state" :key="v" :value="v">{{ v }}</option></select></div></th>
                <th>Enabled<div><select v-model="svcF.enabled" style="font-size:11px;max-width:80px;margin-top:2px"><option value="">all</option><option value="yes">yes</option><option value="no">no</option></select></div></th>
                <th>Exit<div><select v-model="svcF.exit" style="font-size:11px;max-width:110px;margin-top:2px"><option value="">all</option><option value="(none)">none</option><option v-for="v in svcFacets.exit" :key="v" :value="v">{{ v }}</option></select></div></th>
                <th>Restart<div><select v-model="svcF.restart" style="font-size:11px;max-width:110px;margin-top:2px"><option value="">all</option><option v-for="v in svcFacets.restart" :key="v" :value="v">{{ v }}</option></select></div></th>
                <th>Restarts</th>
                <th>Memory</th>
                <th>CPU</th>
                <th>Labels<div><select v-model="svcF.label" style="font-size:11px;max-width:100px;margin-top:2px"><option value="">all</option><option v-for="v in svcFacets.label" :key="v" :value="v">{{ v }}</option></select></div></th>
                <th></th>
              </tr></thead>
              <tbody>
                <template v-for="(row,i) in svcRows" :key="svcKey(row)">
                <tr @click="toggleSvcDetail(svcKey(row))" style="cursor:pointer" :title="'click for details'">
                  <td class="mono">{{ row.unit.name }}<div v-if="row.unit.description" class="muted small" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ row.unit.description }}</div></td>
                  <td class="mono">{{ hostNameById(row.host_id) }}</td>
                  <td><span class="badge" :class="svcBadge(row.unit).cls">{{ svcBadge(row.unit).label }}</span></td>
                  <td>{{ row.unit.enabled ? 'yes' : 'no' }}</td>
                  <td class="mono">{{ unitExit(row.unit) }}</td>
                  <td class="mono">{{ row.unit.restart_policy || '—' }}</td>
                  <td class="mono">{{ row.unit.n_restarts || '—' }}</td>
                  <td class="mono">{{ row.unit.memory_current ? fmtBytes(row.unit.memory_current) : '—' }}</td>
                  <td class="mono">{{ row.unit.cpu_usage_sec ? row.unit.cpu_usage_sec + 's' : '—' }}</td>
                  <td><span class="chip" v-for="l in (row.unit.labels||[])" :key="l">{{ l }}</span></td>
                  <td><a v-if="unitCfgLink(row)" @click.prevent.stop="go(unitCfgLink(row))" :title="row.unit.name + ' config'">⚙ config</a><span v-else class="muted">—</span></td>
                </tr>
                <tr v-if="svcDetail === svcKey(row)">
                  <td colspan="11">
                    <div class="mono small" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:4px 18px;padding:8px 12px;background:var(--surface-app,#f6f6f4);border-radius:6px">
                      <span v-if="row.unit.description"><b>Description</b> — {{ row.unit.description }}</span>
                      <span><b>State</b> — {{ row.unit.state }} / {{ row.unit.sub_state || '?' }} · <b>type</b> {{ row.unit.type || '?' }}</span>
                      <span v-if="row.unit.main_pid"><b>Main PID</b> — {{ row.unit.main_pid }}</span>
                      <span v-if="row.unit.fragment_path"><b>Unit file</b> — {{ row.unit.fragment_path }}</span>
                      <span v-if="row.unit.exec_main_start_timestamp"><b>Last start</b> — {{ row.unit.exec_main_start_timestamp }}</span>
                      <span v-if="row.unit.result && row.unit.result !== 'success'"><b>Last exit</b> — {{ unitExit(row.unit) }}</span>
                      <span v-if="row.unit.restart_policy"><b>Restart</b> — {{ row.unit.restart_policy }}</span>
                      <span v-if="(row.unit.wanted_by||[]).length"><b>Wanted by</b> — {{ row.unit.wanted_by.join(', ') }}</span>
                      <span v-if="(row.unit.after||[]).length"><b>After</b> — {{ row.unit.after.join(', ') }}</span>
                      <span v-if="(row.unit.labels||[]).length"><b>Labels</b> — {{ row.unit.labels.join(', ') }}</span>
                    </div>
                  </td>
                </tr>
                </template>
                <tr v-if="!svcRows.length && !pageLoading"><td colspan="11"><div class="empty">{{ services.length ? 'No units match the current filters.' : 'No service facts (agents must be connected &amp; systemd present).' }}</div></td></tr>
                <tr v-if="!services.length && !pageLoading"><td colspan="10"><div class="empty">No service facts (agents must be connected &amp; systemd present).</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ OBSERVE · CERTIFICATES ============ -->
        <section v-else-if="page==='obs-certs'">
          <h1 class="page">Certificates</h1>
          <p class="page-sub">TLS certificate inventory (M5, R20).</p>
          <div class="toolbar">
            <select :value="certHost" @change="certHost=$event.target.value; loadCerts()" style="max-width:180px">
              <option value="">all hosts</option>
              <option v-for="h in hosts" :key="h.id" :value="h.id">{{ hostOption(h) }}</option>
            </select>
            <input v-model="certQ" placeholder="subject / path" class="mono" @keyup.enter="loadCerts" style="max-width:220px" />
            <label class="fld" style="margin:0;display:flex;align-items:center;gap:8px">
              <span style="margin:0">expires within</span>
              <input type="number" v-model="certDays" min="0" style="width:90px" @keyup.enter="loadCerts" placeholder="days" />
              <button class="btn sm" @click="loadCerts">Apply</button>
            </label>
          </div>
          <div class="card">
            <table class="tbl">
              <thead><tr><th>Subject</th><th>Host</th><th>Expires</th><th>Chain</th><th>Key</th><th>Self-signed</th><th>Used by</th></tr></thead>
              <tbody>
                <tr v-for="(row,i) in certs" :key="i">
                  <td><div class="mono small">{{ row.cert.subject || row.cert.path }}</div></td>
                  <td class="mono">{{ hostNameById(row.host_id) }}</td>
                  <td><span class="badge" :class="certBadge(row.cert).cls">{{ certBadge(row.cert).label }}</span></td>
                  <td><span class="badge" :class="!row.cert.chain_checked?'neutral':(row.cert.chain_valid?'ok':'bad')">{{ !row.cert.chain_checked?'unchecked':(row.cert.chain_valid?'valid':'broken') }}</span></td>
                  <td class="mono">{{ row.cert.key_type || '—' }}</td>
                  <td>{{ row.cert.self_signed ? 'yes' : 'no' }}</td>
                  <td>
                    <template v-for="u in certUsedBy(row)" :key="u.kind+'|'+u.label+'|'+(u.link?1:0)">
                      <a v-if="u.link" @click.prevent="go('obs/configs?host='+row.host_id+'&kind='+u.kind)" style="display:inline-block">{{ u.kind }}·{{ u.label }}</a>
                      <span v-else class="mono" style="display:inline-block">{{ u.kind }}</span>
                    </template>
                    <span v-if="!certUsedBy(row).length" class="muted">—</span>
                  </td>
                </tr>
                <tr v-if="!certs.length && !pageLoading"><td colspan="7"><div class="empty">No certificate facts.</div></td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- ============ OBSERVE · CONFIGS ============ -->
        <section v-else-if="page==='obs-configs'">
          <h1 class="page">Configs</h1>
          <p class="page-sub">HAProxy / Nginx validity &amp; topology (M5, R19).</p>
          <div class="toolbar">
            <select :value="cfgHost" @change="cfgHost=$event.target.value; loadConfigs()" style="max-width:180px">
              <option value="">all hosts</option>
              <option v-for="h in hosts" :key="h.id" :value="h.id">{{ hostOption(h) }}</option>
            </select>
            <select v-model="cfgKind" @change="loadConfigs">
              <option value="">any kind</option><option value="haproxy">haproxy</option><option value="nginx">nginx</option>
            </select>
            <button class="btn sm" @click="loadConfigs">Apply</button>
          </div>
          <div class="card" v-for="(c,i) in configs" :key="i">
            <div class="head">
              <h2>{{ c.kind }} <span class="muted mono small" v-if="c.haproxy || c.nginx">· {{ (c.haproxy||c.nginx).version }}</span></h2>
              <span class="badge" :title="cfgState(c).title" :class="cfgState(c).cls">{{ cfgState(c).t }}</span>
              <a @click.prevent="go('obs/services?host='+c.host_id+'&name='+c.kind)" :title="c.kind + ' service'" style="font-size:12px">◈ {{ c.kind }} service</a>
              <div class="spacer"></div>
              <span class="muted mono small">{{ hostNameById(c.host_id) }}</span>
            </div>
            <div v-if="cfgErr(c)" class="err-box mono small" style="white-space:pre-wrap;margin:8px 0 0;max-height:160px;overflow:auto">{{ cfgErr(c) }}</div>
            <template v-if="c.haproxy">
              <p class="cap">{{ (c.haproxy.backends||[]).length }} backends · {{ (c.haproxy.listeners||[]).length }} listeners</p>
              <table class="tbl" v-if="(c.haproxy.backends||[]).length">
                <thead><tr><th>Backend</th><th>Servers</th><th>Active</th></tr></thead>
                <tbody><tr v-for="b in c.haproxy.backends" :key="b.name"><td class="mono">{{ b.name }}</td><td class="mono">{{ b.servers || '—' }}</td><td class="mono">{{ b.active != null ? b.active : '—' }}</td></tr></tbody>
              </table>
              <table class="tbl" v-if="(c.haproxy.listeners||[]).length">
                <thead><tr><th>Port</th><th>Mode</th><th>TLS cert</th></tr></thead>
                <tbody><tr v-for="l in c.haproxy.listeners" :key="l.port">
                  <td class="mono">{{ l.port }}</td><td class="mono">{{ l.mode }}</td>
                  <td>
                    <a v-if="l.tls" class="mono small" @click.prevent="go('obs/certs?host='+c.host_id+'&q='+encodeURIComponent(l.tls))">{{ l.tls }}</a>
                    <span v-else class="muted">—</span>
                  </td>
                </tr></tbody>
              </table>
            </template>
            <template v-if="c.nginx">
              <p class="cap">{{ (c.nginx.vhosts||[]).length }} vhosts</p>
              <table class="tbl" v-if="(c.nginx.vhosts||[]).length">
                <thead><tr><th>Server</th><th>Listen</th><th>TLS</th><th>Cert</th><th>Upstream</th></tr></thead>
                <tbody><tr v-for="v in c.nginx.vhosts" :key="v.server_name">
                  <td class="mono">{{ v.server_name }}</td><td class="mono">{{ v.port }}</td>
                  <td>{{ v.tls?'yes':'no' }}</td>
                  <td class="mono small">
                    <a v-if="v.tls_cert" @click.prevent="go('obs/certs?host='+c.host_id+'&q='+encodeURIComponent(v.tls_cert))">{{ v.tls_cert }}</a>
                    <span v-else>—</span>
                  </td>
                  <td class="mono small">{{ v.upstream||'—' }}</td>
                </tr></tbody>
              </table>
            </template>
          </div>
          <div class="card" v-if="!configs.length && !pageLoading"><div class="empty">No config facts (haproxy/nginx must be installed).</div></div>
        </section>

        <!-- ============ OBSERVE · ALERTS (M6 engine; rule-management UI M7) ============ -->
        <section v-else-if="page==='obs-alerts'">
          <h1 class="page">Alerts</h1>
          <p class="page-sub">Threshold rules, firing/resolved state, SSE fan-out (R23, R25).</p>
          <div v-if="caps.alerts">
            <div class="card">
              <div class="row" style="margin-bottom:8px">
                <strong>Firing now: {{ alerts.filter(a=>a.state==='firing').length }}</strong>
                <button class="btn sm" @click="loadAlerts">Refresh</button>
              </div>
              <table class="tbl" v-if="alerts.length">
                <thead><tr><th>Severity</th><th>Kind</th><th>Host</th><th>Message</th><th>State</th><th>Started</th></tr></thead>
                <tbody>
                  <tr v-for="a in alerts" :key="a.id">
                    <td><span class="tag" :class="a.severity">{{ a.severity }}</span></td>
                    <td>{{ a.kind }}</td>
                    <td class="mono">{{ hostNameById(a.agent_id) || '—' }}</td>
                    <td>{{ a.message }}</td>
                    <td><span class="badge" :class="a.state==='firing'?'warn':'ok'">{{ a.state }}</span></td>
                    <td>{{ a.started_at ? new Date(a.started_at*1000).toLocaleString() : '—' }}</td>
                  </tr>
                </tbody>
              </table>
              <p v-else-if="!pageLoading" class="muted">No alerts (firing or recently resolved).</p>
            </div>

            <div class="card" style="margin-top:12px">
              <div class="head">
                <h2>Rules</h2>
                <p class="cap">Evaluated every tick over observed facts; one alert per (rule, host, subject).</p>
                <div class="spacer"></div>
                <button class="btn primary sm" :disabled="!isOperator" @click="newRuleForm()">+ New rule</button>
              </div>
              <div v-if="ruleErr" class="err-box" style="margin-bottom:8px">{{ ruleErr }}</div>
              <table class="tbl">
                <thead><tr><th>Name</th><th>Kind</th><th>Selector</th><th>Threshold</th><th>Severity</th><th>Enabled</th><th></th></tr></thead>
                <tbody>
                  <tr v-for="r in rules" :key="r.id">
                    <td>{{ r.name }}</td>
                    <td><span class="chip brand">{{ r.kind }}</span></td>
                    <td class="mono">{{ r.selector }}</td>
                    <td class="mono small">{{ thresholdsLabel(r) }}</td>
                    <td>{{ r.severity }}</td>
                    <td>{{ r.enabled ? 'yes' : 'no' }}</td>
                    <td style="white-space:nowrap">
                      <button class="btn sm" :disabled="!isOperator || ruleBusy===r.id" @click="toggleRule(r)"><span v-if="ruleBusy===r.id" class="spin"></span>{{ r.enabled ? 'Disable' : 'Enable' }}</button>
                      <button class="btn sm" :disabled="!isOperator" @click="editRule(r)">Edit</button>
                      <button class="btn danger sm" :disabled="!isOperator" @click="deleteRule(r.id)">Delete</button>
                    </td>
                  </tr>
                  <tr v-if="!rules.length && !pageLoading"><td colspan="7"><div class="empty"><div class="big">⚠</div>No alert rules.<div style="margin-top:10px"><button class="btn primary sm" :disabled="!isOperator" @click="newRuleForm()">+ New rule</button></div></div></td></tr>
                </tbody>
              </table>

              <div v-if="ruleForm" class="card" style="background:var(--brand-subtle);margin-top:12px">
                <h2>{{ ruleForm.id ? 'Edit rule' : 'New rule' }}</h2>
                <div class="grid cols-2">
                  <label class="fld"><span>Name</span><input v-model="ruleForm.name" placeholder="db ssh down" /></label>
                  <label class="fld"><span>Kind</span>
                    <select v-model="ruleForm.kind">
                      <option value="service_failed">service_failed — unit stuck in failed state</option>
                      <option value="service_restarting">service_restarting — restart rate over NRestarts (M6.1)</option>
                      <option value="cert_expiring">cert_expiring — certificate expiry window</option>
                      <option value="config_invalid">config_invalid — haproxy/nginx native validation</option>
                      <option value="config_drift">config_drift — cross-host config hash divergence (R22)</option>
                      <option value="update_run">update_run — rollout stuck: paused/failed (M8.1, server-level)</option>
                      <option value="update_drift">update_drift — agents behind the store's latest release (M8.1.1, server-level)</option>
                      <option value="security_updates">security_updates — unpatched CVEs on a host (M5.1, security scan)</option>
                    </select>
                  </label>
                  <label class="fld"><span>Selector</span><input v-model="ruleForm.selector" class="mono" placeholder="all | host:ag_x | role:db | tag:k=v" /></label>
                  <label class="fld"><span>Severity</span>
                    <select v-model="ruleForm.severity">
                      <option>info</option><option>warning</option><option>critical</option>
                    </select>
                  </label>
                </div>
                <label class="fld" v-if="ruleForm.kind==='service_failed'" style="max-width:240px"><span>Failed for (minutes)</span>
                  <input type="number" v-model.number="ruleForm.thresh" min="0" /></label>
                <label class="fld" v-if="ruleForm.kind==='service_restarting'" style="max-width:240px"><span>Restart rate (per hour)</span>
                  <input type="number" v-model.number="ruleForm.thresh" min="1" /></label>
                <label class="fld" v-if="ruleForm.kind==='cert_expiring'" style="max-width:240px"><span>Expires within (days)</span>
                  <input type="number" v-model.number="ruleForm.thresh" min="0" /></label>
                <label class="fld" v-if="ruleForm.kind==='config_drift'" style="max-width:240px"><span>Tolerance (extra distinct hashes)</span>
                  <input type="number" v-model.number="ruleForm.thresh" min="0" /></label>
                <p class="cap" v-if="ruleForm.kind==='config_invalid'" style="margin:8px 0 0">No threshold — fires whenever a haproxy/nginx config fails native validation.</p>
                <label class="fld" v-if="ruleForm.kind==='update_run'" style="max-width:320px"><span>Statuses (comma-separated)</span>
                  <input v-model="ruleForm.status" class="mono" placeholder="paused_failure,failed" /></label>
                <p class="cap" v-if="ruleForm.kind==='update_run'" style="margin:8px 0 0">Server-level: the selector is ignored. One alert per stuck run; auto-resolves when the run leaves those statuses (retry/skip/abort/completed).</p>
                <label class="fld" v-if="ruleForm.kind==='update_drift'" style="max-width:280px"><span>Fire when ≥ N agents behind</span>
                  <input type="number" v-model.number="ruleForm.thresh" min="1" /></label>
                <p class="cap" v-if="ruleForm.kind==='update_drift'" style="margin:8px 0 0">Server-level: the selector is ignored. Compares every agent's version against the newest agent release in the store; auto-resolves when the fleet catches up.</p>
                <label class="fld" v-if="ruleForm.kind==='security_updates'" style="max-width:240px"><span>Min severity</span>
                  <select v-model="ruleForm.severityMin">
                    <option>low</option><option>medium</option><option>high</option><option>critical</option>
                  </select></label>
                <label class="fld" v-if="ruleForm.kind==='security_updates'" style="max-width:240px"><span>Fire when ≥ N packages</span>
                  <input type="number" v-model.number="ruleForm.thresh" min="1" /></label>
                <p class="cap" v-if="ruleForm.kind==='security_updates'" style="margin:8px 0 0">Host-scoped: one alert per host with ≥ N packages carrying a CVE at or above the severity floor (from the periodic security scan). Resolves when the host is patched below the floor.</p>
                <div class="toolbar" style="margin-top:10px">
                  <label class="lbl" style="margin:0"><input type="checkbox" v-model="ruleForm.enabled" /> enabled</label>
                  <div class="spacer"></div>
                  <button class="btn sm" @click="ruleForm=null">Cancel</button>
                  <button class="btn primary sm" :disabled="!ruleForm.name || !!ruleBusy" @click="saveRule()">
                    <span v-if="ruleBusy" class="spin"></span>{{ ruleForm.id ? 'Save' : 'Create' }}
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div v-else class="notavail">
            <span class="tag">M6 · not yet available</span>
            <h3>Alert engine not wired on this server</h3>
            <p>Rebuild/upgrade the server to get the M6 alert engine.</p>
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
        theme: document.documentElement.dataset.theme || "light",
        me: null, caps: {}, loginForm: { username: "", password: "" },
        loginErr: "", loginBusy: false, userMenu: false,
        route: (location.hash || "#/fleet").replace(/^#\/?/, ""),
        // Captured from the real location at mount; data so the smoke
        // harness can drive the cleartextLogin branches.
        locProtocol: "", locHostname: "",
        sseStatus: "disconnected", sseWasConnected: false, pageLoading: false,
        groups: [], scope: null, scopeHostIds: null, scopeErr: "",
        fleetFilter: "",
        gsDismissed: (typeof localStorage !== "undefined" && localStorage.getItem("partout.gs.dismissed") === "1"),
        _returnRoute: "", // route to return to after session-expiry re-login
        confirmBox: { open: false, title: "", body: "", mono: "", confirmLabel: "Confirm", variant: "danger", requireText: "", value: "", inputLabel: "", inputPlaceholder: "", inputType: "text", input: "", _resolve: null, _isInput: false },
        navCollapsed: {}, navBadges: { approvals: 0, alerts: 0 },
        paletteOpen: false, paletteQ: "", paletteIdx: 0,
        hosts: [], hostsLoading: false, host: null, hostFacts: null, hostEol: null, serverVersion: "",
        labelDraft: { name: "", service: "" }, roleDraft: "", labelBusy: false,
        exSel: "all", exCmd: "", exArgs: "", exTimeout: 60,
        preview: null, previewLoading: false, executions: [],
        execDetail: null, execOutput: [],
        audit: [], auditKind: "",
        sessions: [], sessionReplay: null, sessionLive: null,
        ptyHost: "", ptyCmd: "bash", ptyBusy: false, ptyErr: "",
        fileHost: "", fileDir: "/", fileEntries: [], fileLoading: false, fileDlg: null, upDlg: null, fileRoot: "",
        updHost: "", jobs: [], jobRuns: [], jobForm: null, jobBusy: false, jobRunBusy: "", jobErr: "", jobRunsDetail: null, jobNote: {}, // per-job dispatch outcome, rendered under the affected row
        updTab: "packages", releases: [], relForm: { version: "", arch: "linux-amd64", kind: "agent", signature: "", file: null, fileB64: "" }, relBusy: false,
        runs: [], runDetail: null, runDetailId: null, runForm: { release_id: "", selector: "all", canary: 1, wave: 25 }, runBusy: false, runNotice: "",
        pkgSel: "", pkgDryRun: false, pkgBusy: false, pkgMsg: "", pkgActions: [], pkgActionDetail: null, pkgChecked: {},
        tasks: [], playbooks: [], updates: [], taskNote: {}, // per-task/playbook dispatch outcome, rendered under the affected row
        secrets: [], policies: [], users: [], presetStatus: null,
        secretForm: { name: "", value: "", selector: "all" }, secretBusy: false,
        userForm: { username: "", password: "", role: "operator" }, userBusy: false,
        provHost: "", provMode: "fresh", provMsg: "", provDetail: null, provBusy: false,
        addHostOpen: false, addHostTab: "manual",
        ahToken: null, ahTokenExpiry: 0, ahTokenBusy: false, ahNow: Date.now(), ahTickInt: null,
        provRuns: [],
        provWiz: { open: false, phase: "target", host: "", mode: "fresh", runId: "", busy: false, run: null, steps: [], sshStatus: null, sshBusy: false, sshErr: "" },
        approvals: [], apprState: "pending", apprBusy: "", apprMsg: "",
        alerts: [], rules: [], ruleForm: null, ruleBusy: "", ruleErr: "",
        taskRuns: [], taskRunDetail: null, taskMsg: "", taskBusy: "",
        taskFormOpen: false, taskCreateBusy: false, taskForm: { name: "", description: "", steps: [] },
        mcpInfo: null, mcpClients: [],
        extStatus: null, extBusy: false,
        security: [], secBusy: false, secPatchBusy: false,
        services: [], svcF: { unit: "", host: "", state: "", enabled: "", exit: "", restart: "", label: "" }, svcDetail: null, svcGroupName: "", svcGroupBusy: false, alertPrefill: null,
        certs: [], certDays: "", certHost: "", certQ: "", certsConfigs: [],
        configs: [], cfgKind: "", cfgHost: "",
        pw: { current: "", next: "" }, pwMsg: "", pwErr: "",
        toasts: [],
        _provOnce: {},
      };
    },
    computed: {
      loggedIn() { return !!this.token; },
      // Services header filters: AND-combined client-side over the loaded
      // rows (the API returns the full unpaginated list). Facets are the
      // distinct values actually present, so every option is reachable.
      svcFAny() { return Object.values(this.svcF).some((v) => v !== ""); },
      // Selectors target hosts: a host filter pins one; otherwise the
      // filtered set spans the whole fleet ("all" is a valid selector).
      svcTarget() { return this.svcF.host ? "host:" + this.svcF.host : "all"; },
      // Human gloss for the selector in the action bar: "all" on its own
      // reads like "no target chosen", so name what it actually covers.
      svcTargetHint() {
        return this.svcF.host ? "this host" : "every host in the fleet";
      },
      svcRows() {
        const f = this.svcF;
        return this.services.filter((row) => {
          const u = row.unit;
          if (f.unit && !u.name.toLowerCase().includes(f.unit.toLowerCase())) return false;
          if (f.host && row.host_id !== f.host) return false;
          if (f.state && u.state !== f.state) return false;
          if (f.enabled && (u.enabled ? "yes" : "no") !== f.enabled) return false;
          if (f.exit) {
            const e = this.unitExit(u);
            if (f.exit === "(none)" ? e !== "—" : e !== f.exit) return false;
          }
          if (f.restart && u.restart_policy !== f.restart) return false;
          if (f.label && !(u.labels || []).includes(f.label)) return false;
          return true;
        });
      },
      svcFacets() {
        const set = (fn) => [...new Set(this.services.map(fn).filter((v) => v !== "" && v != null))].sort();
        const labels = new Set();
        for (const r of this.services) for (const l of (r.unit.labels || [])) if (l) labels.add(l);
        return {
          state: set((r) => r.unit.state),
          exit: set((r) => { const e = this.unitExit(r.unit); return e === "—" ? "" : e; }),
          restart: set((r) => r.unit.restart_policy),
          label: [...labels].sort(),
        };
      },
      parts() { return this.route.split("?")[0].split("/").filter(Boolean); },
      // Query string of the current hash route (cross-link params: host/name/q/kind).
      routeQuery() {
        const i = this.route.indexOf("?");
        if (i < 0) return {};
        const out = {};
        for (const kv of this.route.slice(i + 1).split("&")) {
          if (!kv) continue;
          const [k, v] = kv.split("=");
          try { out[decodeURIComponent(k)] = decodeURIComponent(v || ""); } catch (e) { }
        }
        return out;
      },
      page() {
        const p = this.parts;
        // An id-less detail route (e.g. a hand-typed #/host) falls back to its
        // list page rather than rendering a detail view that would fire doomed
        // GET /hosts/ requests (404s in the console).
        if (p[0] === "host") return p[1] ? "host" : "fleet";
        if (p[0] === "exec") return p[1] ? "exec" : "execute";
        if (p[0] === "session") return p[1] ? "session" : "sessions";
        if (p[0] === "obs") return "obs-" + (p[1] || "services");
        return p[0] || "fleet";
      },
      p1() { return this.parts[1] || ""; },
      p2() { return this.parts[2] || ""; },
      // Wizard live view: the run's last state change is >2 min old and it is
      // not terminal — it may be stuck (a server restart mid-run is reaped at
      // boot; anything else deserves an explicit hint instead of "Connecting…").
      provWizStalled() {
        const r = this.provWiz.run;
        return !!(r && !this.provTerminal(r.state) && r.updated && Date.now() / 1000 - r.updated > 120);
      },
      isOperator() { return ["operator", "admin"].includes(this.me?.role); },
      isAdmin() { return this.me?.role === "admin"; },
      presetMissing() {
        if (!this.presetStatus) return 0;
        const rows = [...(this.presetStatus.policies || []), ...(this.presetStatus.alert_rules || [])];
        return rows.filter(r => !r.present).length;
      },
      presetMissingList() {
        if (!this.presetStatus) return "";
        const rows = [...(this.presetStatus.policies || []), ...(this.presetStatus.alert_rules || [])];
        return rows.filter(r => !r.present).map(r => r.name).join(", ");
      },
      locationHost() { return (typeof location !== "undefined" && location.host) ? location.host : "server:8443"; },
      // True when the SPA itself was served over cleartext HTTP from a host
      // that is not loopback: the login password (and every later session
      // token) crosses the network unencrypted. Mirror of the doctor TLS
      // warning — the browser is the other place an operator can learn this.
      // locProtocol/locHostname are captured from the real location at mount
      // (and are data so the smoke harness can drive both branches).
      cleartextLogin() {
        if (this.locProtocol !== "http:") return false;
        return !this.isLoopbackHost(this.locHostname);
      },
      ahCmd() {
        if (!this.ahToken) return "";
        return "PARTOUT_SERVER=" + this.locationHost + " PARTOUT_TOKEN=" + this.ahToken + " partout --mode=agent";
      },
      ahTtlLeft() {
        if (!this.ahTokenExpiry) return "—";
        return Math.max(0, this.ahTokenExpiry - Math.floor(this.ahNow / 1000));
      },
      provModeHint() {
        return this.provMode === "fresh"
          ? "fresh: clean slate — stops and removes any existing partout agent + identity on the host, then enrolls a brand-new agent. Use for new hosts or a reset."
          : "join: non-destructive in-place binary update for a host that already has an enrolled agent (identity preserved). Use for upgrades.";
      },
      provWizModeShort() {
        return this.provWiz.mode === "fresh" ? "clean slate, enroll a brand-new agent" : "in-place update, identity preserved";
      },
      // Full guidance for the selected mode (fresh/join), shown in the wizard's
      // target phase.
      provWizModeHint() {
        return this.provWiz.mode === "fresh"
          ? "fresh — clean slate: stops and removes any existing partout agent + identity on the target, then enrolls a brand-new one. Use for a NEW host."
          : "join — non-destructive in-place binary update for a host that already has an enrolled agent (identity preserved). Use for an upgrade.";
      },
      // Soft hint only: does the target's host part look like an already-
      // enrolled host? Best-effort hostname/name match; null when no match.
      provWizKnownHost() {
        const target = (this.provWiz.host || "").trim();
        if (!target) return null;
        const hpart = target.split("@").pop().split(":")[0].toLowerCase();
        if (!hpart) return null;
        for (const h of this.hosts) {
          const name = (h.name || "").toLowerCase();
          const host = (h.hostname || "").toLowerCase();
          if (hpart === name || hpart === host) return h.name || h.hostname || h.id;
        }
        return null;
      },
      provWizPhaseLabel() {
        return ({ target: "Step 1 of 3 — target", confirm: "Step 2 of 3 — review", live: "Step 3 of 3 — progress" })[this.provWiz.phase] || "";
      },
      // Is the current page's primary list empty? Drives the "Loading…"
      // indicator: shown only while loading AND empty, so a reconnect (data
      // already present) never flashes it.
      pagePrimaryEmpty() {
        switch (this.page) {
          case "exec": return !this.executions.length;
          case "audit": return !this.audit.length;
          case "sessions": return !this.sessions.length;
          case "files": return !this.fileEntries.length;
          case "jobs": return !this.jobs.length;
          case "tasks": return !this.tasks.length;
          case "updates": return !this.releases.length && !this.runs.length && !this.security.length;
          case "secrets": return !this.secrets.length;
          case "policies": return !this.policies.length;
          case "approvals": return !this.approvals.length;
          case "obs-alerts": return !this.alerts.length && !this.rules.length;
          case "obs-services": return !this.services.length;
          case "obs-certs": return !this.certs.length;
          case "obs-configs": return !this.configs.length;
          case "users": return !this.users.length;
          default: return false;
        }
      },
      initials() { return (this.me?.username || "?").slice(0, 2).toUpperCase(); },
      sseDot() { return this.sseStatus === "connected" ? "ok" : this.sseStatus === "reconnecting" ? "warn" : "down"; },
      hostMap() { const m = {}; for (const h of this.hosts) m[h.id] = h; return m; },
      crumbHost() { return this.page === "host" ? (this.hostName(this.host) || this.p1) : ""; },
      crumbPage() { if (this.page === "host") return this.p2 || "overview"; if (this.page === "exec") return "execution"; return ""; },
      health() {
        const c = { connected: 0, disconnected: 0, pending: 0 };
        for (const h of this.scopedHosts) if (c[h.state] !== undefined) c[h.state]++;
        return c;
      },
      // Scope is a host-group filter. Resolution is server-authoritative
      // (the /hosts?selector= preview endpoint), so role:/tag:/multi-host
      // selectors resolve exactly as at dispatch time — the old local
      // host:-only regex silently showed the whole fleet for those.
      scopedHosts() {
        if (!this.scope) return this.hosts;
        if (!this.scopeHostIds) return [];
        const ids = new Set(this.scopeHostIds);
        return this.hosts.filter(h => ids.has(h.id));
      },
      // Fleet table rows: the scope subset, further narrowed by the free-text
      // filter (matches name, id, hostname, OS, roles, tag keys).
      visibleHosts() {
        const q = this.fleetFilter.trim().toLowerCase();
        if (!q) return this.scopedHosts;
        return this.scopedHosts.filter(h => {
          const hay = [this.hostName(h), h.id, h.hostname || "", h.os || "",
            (h.roles || []).join(" "), Object.keys(h.tags || {}).join(" ")].join(" ").toLowerCase();
          return hay.includes(q);
        });
      },
      paletteItems() {
        const q = this.paletteQ.trim().toLowerCase();
        const out = [];
        for (const g of this.navGroups()) {
          for (const n of g.items) {
            if (!this.navEnabled(n)) continue;
            out.push({ kind: "page", group: g.label, key: n.key, label: n.label, icon: n.icon, sub: "" });
          }
        }
        for (const h of this.hosts) {
          out.push({ kind: "host", group: "Host", key: h.id, label: this.hostName(h), icon: "▦", sub: h.id });
        }
        const f = q ? out.filter(x => (x.label + " " + x.sub + " " + x.group).toLowerCase().includes(q)) : out;
        return f.slice(0, 40);
      },
      auditKinds() { return [...new Set(this.audit.map(a => a.kind))]; },
      meName() { return (this.me && this.me.username) || ""; },
    },
    methods: {
      fmtAgo, fmtDate, fmtBytes, agentBadge, execBadge, runBadge, taskRunBadge, stepBadge, pkgActionBadge, provBadge, provStepBadge, certBadge, svcBadge, eolBadge, hostName, hostOption,
      // Global toast notifications (consistent success/error feedback across
      // every page). kind: ok|err|info. ttl ms (default 4000).
      notify(kind, msg, ttl = 4000) {
        const id = Date.now() + "-" + Math.random().toString(36).slice(2, 7);
        this.toasts.push({ id, kind, msg });
        setTimeout(() => this.dismissToast(id), ttl);
        return id;
      },
      dismissToast(id) { this.toasts = this.toasts.filter(t => t.id !== id); },
      async api(path, opts = {}) {
        const headers = { ...(opts.headers || {}) };
        if (this.token) headers["Authorization"] = "Bearer " + this.token;
        if (opts.body !== undefined && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
        const method = opts.method || (opts.body !== undefined ? "POST" : "GET");
        // Global feedback for write actions (POST/PUT/DELETE). GET loads are
        // usually transient/polling and reset their own state, so they stay
        // quiet unless the caller opts in with opts.toast. opts.silent always
        // wins (e.g. high-frequency PTY input/resize).
        const isWrite = method !== "GET";
        const wantToast = (isWrite && !opts.silent) || opts.toast;
        let res;
        try {
          res = await fetch("/api/v1" + path, {
            method, headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
          });
        } catch (e) {
          // Transport failure (server down, network blip): fetch rejects before
          // any status handling, so surface it here rather than staying silent.
          if (wantToast) this.notify("err", "network error: " + (e && e.message ? e.message : "request failed"));
          throw new ApiError(0, "network error", "network_error", null);
        }
        if (res.status === 401) { this.sessionExpired(); throw new ApiError(401, "unauthorized"); }
        if (res.status === 503) {
          this.refreshCaps();
          if (wantToast) this.notify("err", "feature disabled in this build (503)");
          throw new ApiError(503, "disabled");
        }
        let data = null; try { data = await res.json(); } catch (e) { }
        if (!res.ok) {
          const msg = (data && data.message) || String(res.status);
          if (wantToast) this.notify("err", msg + (data && data.code ? " (" + data.code + ")" : ""));
          throw new ApiError(res.status, msg, data && data.code, data);
        }
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
      // Navigation IA: grouped by task, ordered common → advanced. Sections
      // are collapsible (state persisted); capability + role gating stays
      // per-item so disabled/admin entries remain discoverable.
      navGroups() {
        return [
          { key: "fleet", label: "Fleet", items: [
            { key: "fleet", label: "Hosts", icon: "▦", cap: "hosts" },
            { key: "execute", label: "Execute", icon: "❯", cap: "exec" },
            { key: "sessions", label: "Sessions", icon: "▤", cap: "sessions" },
            { key: "files", label: "Files", icon: "🗀", cap: "files" },
            { key: "updates", label: "Updates", icon: "⇪", cap: "packages" },
          ] },
          { key: "automation", label: "Automation", items: [
            { key: "jobs", label: "Jobs", icon: "◷", cap: "jobs" },
            { key: "tasks", label: "Tasks & Playbooks", icon: "⚙", cap: "tasks" },
          ] },
          { key: "observe", label: "Observe", items: [
            { key: "obs-alerts", label: "Alerts", icon: "⚠", cap: "alerts", badge: "alerts" },
            { key: "obs-services", label: "Services", icon: "◈", cap: "observe" },
            { key: "obs-configs", label: "Configs", icon: "⌘", cap: "observe" },
            { key: "obs-certs", label: "Certificates", icon: "✦", cap: "observe" },
          ] },
          { key: "governance", label: "Governance", items: [
            { key: "approvals", label: "Approvals", icon: "☑", cap: "approvals", badge: "approvals" },
            { key: "policies", label: "Policies", icon: "§", cap: "policies" },
            { key: "secrets", label: "Secrets", icon: "🔒", cap: "secrets" },
            { key: "audit", label: "Audit", icon: "≡", cap: "audit" },
          ] },
          { key: "admin", label: "Admin", items: [
            { key: "provision", label: "Provision", icon: "➕", cap: "provision", admin: true, badge: "provision" },
            { key: "users", label: "Users", icon: "👤", cap: "users", admin: true },
            { key: "mcp", label: "MCP", icon: "⟨⟩", cap: "mcp" },
          ] },
        ];
      },
      navEnabled(n) { return this.capOn(n.cap) && (!n.admin || this.isAdmin); },
      navTitle(n) {
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
      // Attention badges (pending approvals / firing alerts): loaded once at
      // sign-in, then refreshed on the matching SSE events — live, no
      // polling. A 403 (feature off for this role/build) leaves 0.
      navBadge(n) { return (n.badge && this.navBadges[n.badge]) || 0; },
      navGroupBadge(g) { return g.items.reduce((s, n) => s + this.navBadge(n), 0); },
      async loadNavBadges() {
        try { const d = await this.api("/approvals?state=pending", { silent: true }); this.navBadges.approvals = (d.approvals || []).length; } catch (e) { /* no badge */ }
        try { const d = await this.api("/alerts", { silent: true }); this.navBadges.alerts = (d.alerts || []).length; } catch (e) { /* no badge */ }
        // Provision: runs parked at the host-key TOFU gate. The run does not
        // fail or time out on its own, so this badge is the standing signal
        // that an admin action is waiting.
        try { const d = await this.api("/provision-runs", { silent: true }); this.navBadges.provision = (d.items || []).filter(r => r.state === "key_confirm").length; } catch (e) { /* no badge */ }
      },
      // Collapsible sections: persisted in localStorage, Admin collapsed by
      // default; the section holding the active page auto-expands.
      isNavCollapsed(key) { return !!this.navCollapsed[key]; },
      toggleNavGroup(key) {
        this.navCollapsed = { ...this.navCollapsed, [key]: !this.navCollapsed[key] };
        this.saveNavCollapsed();
      },
      ensureNavExpanded() {
        const g = this.navGroups().find(x => x.items.some(n => n.key === this.page));
        if (g && this.navCollapsed[g.key]) {
          this.navCollapsed = { ...this.navCollapsed, [g.key]: false };
          this.saveNavCollapsed();
        }
      },
      loadNavCollapsed() {
        try {
          const raw = localStorage.getItem(LS_NAV_COLLAPSED);
          this.navCollapsed = raw ? (JSON.parse(raw) || {}) : { admin: true };
        } catch (e) { this.navCollapsed = { admin: true }; }
      },
      saveNavCollapsed() {
        try { localStorage.setItem(LS_NAV_COLLAPSED, JSON.stringify(this.navCollapsed)); } catch (e) { }
      },
      // Scope: a host group acts as a fleet filter (server-resolved).
      async setScope(name) {
        if (this.scope === name) { this.clearScope(); return; }
        this.scope = name; this.scopeHostIds = null; this.scopeErr = "";
        if (this.page !== "fleet") this.go("fleet");
        await this.resolveScope();
      },
      clearScope() { this.scope = null; this.scopeHostIds = null; this.scopeErr = ""; },
      async resolveScope() {
        if (!this.scope) return;
        const g = this.groups.find(x => x.name === this.scope);
        if (!g) { this.scopeHostIds = []; this.scopeErr = "group not found"; return; }
        const sel = (g.selector || "").trim() || "all";
        try {
          const d = await this.api("/hosts?selector=" + encodeURIComponent(sel), { silent: true });
          this.scopeHostIds = (d.items || []).map(i => i.id);
          this.scopeErr = "";
        } catch (e) { this.scopeHostIds = []; this.scopeErr = e.message || "unresolved selector"; }
      },
      // Theme toggle (topbar): light/dark, persisted to localStorage.
      // The <html data-theme> attribute is set pre-paint by index.html so
      // the first render never flashes the wrong theme.
      toggleTheme() {
        this.theme = this.theme === "dark" ? "light" : "dark";
        document.documentElement.dataset.theme = this.theme;
        try { localStorage.setItem(LS_THEME, this.theme); } catch (e) {}
      },
      // Command palette (⌘K / Ctrl-K): jump to any enabled page or host.
      openPalette() {
        this.paletteOpen = true; this.paletteQ = ""; this.paletteIdx = 0;
        this.$nextTick(() => { const el = this.$refs.paletteInput; if (el) el.focus(); });
      },
      closePalette() { this.paletteOpen = false; },
      paletteMove(d) {
        const n = this.paletteItems.length;
        if (!n) return;
        this.paletteIdx = (this.paletteIdx + d + n) % n;
      },
      paletteRun() { const it = this.paletteItems[this.paletteIdx]; if (it) this.paletteGo(it); },
      paletteGo(it) { this.closePalette(); this.go(it.kind === "host" ? "host/" + it.key : it.key); },
      onGlobalKey(e) {
        if (e.key === "Escape" && this.confirmBox.open) { this.confirmBoxNo(); return; }
        if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
          e.preventDefault();
          if (this.paletteOpen) this.closePalette(); else this.openPalette();
        }
      },
      async refreshCaps() { try { this.caps = await this.api("/capabilities"); } catch (e) { this.caps = {}; } },
      async loadVersion() { try { const d = await this.api("/version"); this.serverVersion = d.version || ""; } catch (e) { } },
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
      async afterLogin() {
        // Return the operator to where an expired session interrupted them
        // (sessionExpired records the route before signing out). Cleared on
        // use and on explicit sign-out, so it never goes stale.
        const back = this._returnRoute || ""; this._returnRoute = "";
        if (back && back !== "fleet") this.go(back);
        await Promise.all([this.refreshCaps(), this.loadMe(), this.loadGroups()]); this.startSSE(); this.loadPageData();
      },
      // Sign-out because the session token was rejected (401): keep the
      // operator's place so sign-in returns them to what they were doing,
      // and say why — a silent drop to the login page reads as a bug, and a
      // server restart (12h in-memory sessions) invalidates everyone.
      // Idempotent: the sign-out itself triggers unauthenticated page loads
      // whose 401s re-enter this path — the first capture wins, and a second
      // toast would just be noise.
      sessionExpired() {
        if (!this.token) return;
        const here = this.route || ""; // signOut clears the slot; capture first
        this.signOut();
        this._returnRoute = here;
        this.notify("warn", "Session expired — sign in to continue", 8000);
      },
      signOut() {
        this.token = ""; localStorage.removeItem(LS_TOKEN); this.me = null; this._returnRoute = "";
        this.stopSSE(); this.sseStatus = "disconnected"; this.sseWasConnected = false; this.go("fleet");
      },
      async changePassword() {
        this.pwMsg = ""; this.pwErr = "";
        try {
          // The server expects old_password/new_password and, on success,
          // invalidates the caller's token and returns a fresh one — adopt it
          // so the session stays live.
          const d = await this.api("/auth/password", { method: "POST", body: { old_password: this.pw.current, new_password: this.pw.next } });
          if (d && d.token) { this.token = d.token; localStorage.setItem(LS_TOKEN, d.token); }
          this.pwMsg = "Password updated."; this.pw.current = ""; this.pw.next = "";
          this.notify("ok", "password updated");
        } catch (e) { this.pwErr = e.message; }
      },
      startSSE() {
        this.stopSSE();
        this.sseStatus = "reconnecting";
        let opened = false;
        const es = new EventSource("/api/v1/events" + (this.token ? "?token=" + encodeURIComponent(this.token) : ""));
        this._es = es;
        es.onopen = () => {
          this.sseStatus = "connected";
          this.sseWasConnected = true;
          // Reconcile only on RE-connect: the first open follows the initial
          // page load (mounted/afterLogin already fetched); reloading here
          // would double every list request on every page load.
          if (opened) {
            this.loadPageData();
            // Events fired while the stream was down are gone; if the wizard
            // is watching a still-non-terminal run, catch it up once.
            if (this.provWiz.open && this.provWiz.runId && this.provWiz.run && !this.provTerminal(this.provWiz.run.state)) this.provWizRefresh();
          }
          opened = true;
        };
        es.onerror = () => { this.sseStatus = "reconnecting"; };
        const kinds = ["host.state", "execution.state", "audit.event", "job.run", "job.run-parked", "task.run", "package.action", "session.data", "session.opened", "session.result", "session.interrupted", "file.action", "approval.requested", "approval.approved", "approval.denied", "alert.firing", "alert.resolved", "provision.start", "provision.step", "provision.key_confirm", "provision.connected", "provision.failed", "provision.cancelled", "provision.handoff", "update.run", "update.host"];
        for (const k of kinds) es.addEventListener(k, (e) => { let p; try { p = JSON.parse(e.data); } catch (err) { p = e.data; } this.onSSEEvent(k, p); });
      },
      stopSSE() { if (this._es) { this._es.close(); this._es = null; } },
      onSSEEvent(kind, p) {
        // The onboarding wizard is event-driven: any provision.* event for
        // the run it is watching refetches it (the "no polling" invariant —
        // ui-guidelines §10). The wizard was the one remaining poller.
        if (kind && kind.indexOf("provision.") === 0 && this.provWiz.open && this.provWiz.runId && p && p.run_id === this.provWiz.runId) this.provWizRefresh();
        if (kind === "host.state") this.loadHosts();
        else if (kind === "execution.state") { if (this.page === "execute") this.loadExecutions(); if (this.page === "exec") this.loadExecDetail(); }
        else if (kind === "audit.event" && this.page === "audit") this.loadAudit();
        else if ((kind === "job.run" || kind === "job.run-parked") && this.page === "jobs") { this.loadJobs(); if (this.jobRunsDetail) this.loadJobRuns(this.jobRunsDetail.job_id); }
        else if (kind === "task.run" && this.page === "tasks") { this.loadTasks(); this.loadPlaybooks(); this.loadTaskRuns(); }
        else if (kind === "package.action" && this.page === "updates") { this.loadUpdates(); this.loadPkgActions(); }
        else if ((kind === "update.run" || kind === "update.host") && this.page === "updates") { this.loadRuns(); if (this.runDetailId) this.openRun(this.runDetailId); }
        else if (kind === "provision.failed") {
          // Terminal failure: notify on ANY page (the run may have been
          // started while the operator was elsewhere) and expand the run's
          // steps if the Provision page is open.
          if (this.provOnce(kind, p.run_id)) this.notify("err", "provision " + (p.host || p.run_id || "") + " failed: " + firstLine(p.error || "unknown error"), 10000);
          if (this.page === "provision") { this.loadProvRuns(); if (p.run_id) this.loadProvDetail(p.run_id); }
        }
        else if (kind === "provision.cancelled") {
          if (this.provOnce(kind, p.run_id)) this.notify("info", "provision " + (p.host || p.run_id || "") + " cancelled" + (p.error ? " — " + firstLine(p.error) : ""), 8000);
          this.loadNavBadges();
          if (this.page === "provision") this.loadProvRuns();
        }
        else if (kind === "provision.key_confirm") {
          // Host-key TOFU gate: the run pauses HERE until an admin confirms
          // the fingerprint. It is a long-lived wait, not a failure — and
          // nothing else moves it — so notify on ANY page and keep the
          // Provision nav badge counting it.
          if (this.provOnce(kind, p.run_id)) this.notify("warn", "provision " + (p.host || p.run_id || "") + " awaits host-key confirmation (" + (p.key_type || "host key") + " " + (p.fingerprint || "").slice(0, 20) + "…) — confirm or deny on the Provision page", 15000);
          this.loadNavBadges();
          if (this.page === "provision") this.loadProvRuns();
        }
        else if (kind === "provision.connected" || kind === "provision.handoff") {
          if (this.provOnce(kind, p.run_id)) this.notify("ok", kind === "provision.handoff" ? "provision " + (p.host || p.run_id || "") + " reached handoff — non-systemd host, complete the install manually" : "provision " + (p.host || p.run_id || "") + " connected — host enrolled", 8000);
          this.loadNavBadges();
          if (this.page === "provision") this.loadProvRuns();
        }
        else if (kind.startsWith("provision.") && this.page === "provision") { this.loadProvRuns(); if (this.provDetail) this.loadProvDetail(this.provDetail.run.id); }
        else if (kind === "file.action" && this.page === "files") this.listFiles();
        else if (kind === "session.data") { if (this.page === "session") this._onSessionData(p); }
        else if (kind === "session.opened") { if (this.page === "session") this.loadSessionReplay(); }
        else if (kind === "session.result") {
          if (this.page === "session") {
            if (p && this._term && p.session_id === this.p1) {
              this._termFinalize(p);
              setTimeout(() => { if (this.page === "session") { this._destroyTerm(); this.loadSessionReplay(); } }, 1500);
            } else {
              this._destroyTerm();
              this.loadSessionReplay();
            }
          }
        }
        else if (kind === "session.interrupted") {
          if (this.page === "session") { this._destroyTerm(); this.loadSessionReplay(); }
          else if (this.page === "sessions") this.loadSessions();
        }
        else if (kind === "approval.requested" || kind === "approval.approved" || kind === "approval.denied") { this.loadNavBadges(); if (this.page === "approvals") this.loadApprovals(); }
        else if (kind === "alert.firing" || kind === "alert.resolved") { this.loadNavBadges(); if (this.page === "obs-alerts") this.loadAlerts(); }
      },
      async loadPageData() {
        // Central loading flag: a page shows a "Loading…" indicator (and
        // suppresses its empty state) while its data is fetched, so an empty
        // table during the first load isn't mistaken for "there is nothing".
        this.pageLoading = true;
        try { await this._loadPageDataInner(); } finally { this.pageLoading = false; }
      },
      async _loadPageDataInner() {
        // Files, Updates, Jobs and the Observe pages need the host list (default
        // host selection, per-host run target, host filter dropdowns). Load it
        // first if a deep link lands here before the fleet page ever ran.
        if (["exec", "audit", "approvals", "files", "updates", "jobs", "tasks", "sessions", "provision", "obs-services", "obs-certs", "obs-configs", "obs-alerts"].includes(this.page) && !this.hosts.length) {
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
          case "tasks": await this.loadTasks(); await this.loadPlaybooks(); await this.loadTaskRuns(); break;
          case "updates": await this.loadUpdates(); this.loadPkgActions(); this.loadExtStatus(); this.loadReleases(); this.loadRuns(); break;
          case "secrets": await this.loadSecrets(); break;
          case "policies": await this.loadPolicies(); await this.loadPreset(); break;
          case "approvals": await this.loadApprovals(); break;
          case "obs-alerts": await this.loadAlerts(); this.loadRules();
            if (this.alertPrefill) {
              const p = this.alertPrefill; this.alertPrefill = null;
              this.newRuleForm();
              this.ruleForm.selector = p.selector;
              this.ruleForm.kind = p.kind;
              this.notify("info", "Rule form pre-filled from the Services filter — name it, review, then save", 6000);
            }
            break;
          case "mcp": await this.loadMcp(); this.loadMcpClients(); break;
          case "provision": await this.loadProvRuns(); break;
          case "users": await this.loadUsers(); break;
          case "obs-services": this.syncObserveQuery(); await this.loadServices(); break;
          case "obs-certs": this.syncObserveQuery(); await this.loadCerts(); break;
          case "obs-configs": this.syncObserveQuery(); await this.loadConfigs(); break;
        }
      },
      async loadHosts() { this.hostsLoading = true; try { const d = await this.api("/hosts"); this.hosts = d.items || []; } catch (e) { this.hosts = []; } finally { this.hostsLoading = false; } if (this.scope) this.resolveScope(); },
      async loadHostDetail() {
        // Overview comes from GET /hosts/{id} (state/uuid/version/timestamps);
        // GET /hosts/{id}/facts only returns {host_id, ts, facts}.
        this.host = null; this.hostFacts = null; this.hostEol = null;
        if (!this.p1) return; // id-less route: nothing to load (never GET /hosts/)
        try { this.host = await this.api("/hosts/" + encodeURIComponent(this.p1)); } catch (e) { this.host = null; }
        this.labelDraft = {
          name: (this.host && this.host.tags && this.host.tags.name) || "",
          service: (this.host && this.host.tags && this.host.tags.service) || "",
        };
        try { this.hostFacts = await this.api("/hosts/" + encodeURIComponent(this.p1) + "/facts"); } catch (e) { this.hostFacts = null; }
        try { this.hostEol = await this.api("/hosts/" + encodeURIComponent(this.p1) + "/eol"); } catch (e) { this.hostEol = null; }
      },
      async loadExecutions() { try { const d = await this.api("/executions"); this.executions = d.items || []; } catch (e) { this.executions = []; } },
      async loadExecDetail() {
        this.execDetail = null; this.execOutput = [];
        if (!this.p1) return; // id-less route: never GET /executions/
        try { this.execDetail = await this.api("/executions/" + encodeURIComponent(this.p1)); } catch (e) { this.execDetail = null; return; }
        try { this.execOutput = (await this.api("/executions/" + encodeURIComponent(this.p1) + "/output")) || []; } catch (e) { this.execOutput = []; }
      },
      outFor(runId) { return this.execOutput.filter(o => o.run_id === runId); },
      async saveHostLabels() {
        const id = this.p1;
        this.labelBusy = true;
        try {
          for (const [key, val] of [["name", this.labelDraft.name.trim()], ["service", this.labelDraft.service.trim()]]) {
            const url = `/hosts/${encodeURIComponent(id)}/tags/${encodeURIComponent(key)}`;
            if (val) await this.api(url, { method: "PUT", body: { value: val }, silent: true });
            else await this.api(url, { method: "DELETE", silent: true });
          }
          await this.loadHostDetail();
          this.notify("ok", "labels saved");
        } catch (e) { /* toast shown by api() */ } finally { this.labelBusy = false; }
      },
      // Friendly name for a raw agent id (historical rows that only carry the
      // id). Falls back to the id itself when the host list hasn't loaded or
      // the agent is gone.
      hostNameById(id) {
        if (!id) return "";
        const h = this.hosts.find(x => x.id === id);
        return h ? this.hostName(h) : id;
      },
      async removeHost() {
        const id = this.p1;
        const label = this.hostNameById(id);
        if (!await this.askConfirm({ title: "Remove host", body: "This deletes the agent and all its data (runs, sessions, files, facts, tags, roles) and revokes it from the fleet — the host can never rejoin with its current identity. To reuse the machine, re-provision it in fresh mode.", mono: label + " (" + id + ")", confirmLabel: "Remove host", variant: "danger", requireText: id })) return;
        try {
          await this.api("/hosts/" + encodeURIComponent(id), { method: "DELETE" });
          this.notify("ok", "host removed");
          this.host = null;
          this.go("fleet");
          this.loadHosts();
        } catch (e) { /* toast shown by api() */ }
      },
      async addRole() {
        const role = this.roleDraft.trim();
        if (!role) return;
        try {
          await this.api(`/hosts/${encodeURIComponent(this.p1)}/roles/${encodeURIComponent(role)}`, { method: "PUT" });
          this.roleDraft = "";
          await this.loadHostDetail();
          this.notify("ok", `role "${role}" added`);
        } catch (e) { /* toast shown by api() */ }
      },
      async removeRole(role) {
        try {
          await this.api(`/hosts/${encodeURIComponent(this.p1)}/roles/${encodeURIComponent(role)}`, { method: "DELETE" });
          await this.loadHostDetail();
          this.notify("ok", `role "${role}" removed`);
        } catch (e) { /* toast shown by api() */ }
      },
      async loadAudit() { const q = this.auditKind ? "?kind=" + encodeURIComponent(this.auditKind) : ""; try { const d = await this.api("/audit" + q); this.audit = d.items || []; } catch (e) { this.audit = []; } },
      async loadSessions() { try { const d = await this.api("/sessions"); this.sessions = d.sessions || d.items || []; } catch (e) { this.sessions = []; } },
      async loadSessionReplay() {
        this.sessionReplay = null;
        this.sessionLive = null;
        this._destroyTerm();
        if (!this.p1) return; // id-less route: never GET /sessions//replay
        // Live session → xterm.js terminal; otherwise the recorded replay.
        try {
          const s = await this.api("/sessions/" + encodeURIComponent(this.p1));
          this.sessionLive = s;
          if (s.state === "open") { this.$nextTick(() => this.mountTerminal(s)); return; }
        } catch (e) { this.sessionLive = null; }
        try { this.sessionReplay = await this.api("/sessions/" + encodeURIComponent(this.p1) + "/replay"); } catch (e) { this.sessionReplay = null; }
      },
      // --- live PTY (xterm.js; M7) ---
      async openSession() {
        this.ptyBusy = true; this.ptyErr = "";
        try {
          const s = await this.api("/sessions", { method: "POST", body: { agent_id: this.ptyHost, cmd: this.ptyCmd, cols: 80, rows: 24, record: true } });
          if (s.state === "approval_required") { this.ptyErr = "Session open parked on approval " + (s.approval_id || "") + " — approve it on the Approvals page."; return; }
          const id = s.session_id || s.id;
          if (id) this.go("session/" + id);
          else this.ptyErr = "no session id in response";
        } catch (e) { this.ptyErr = e.message; } finally { this.ptyBusy = false; }
      },
      async closeSession() {
        if (!await this.askConfirm({ title: "Close session", body: "The PTY receives SIGHUP and the terminal closes.", confirmLabel: "Close", variant: "danger" })) return;
        try { await this.api("/sessions/" + encodeURIComponent(this.p1) + "/close", { method: "POST" }); this.notify("ok", "session closed"); } catch (e) { /* toast shown by api() */ }
        this.loadSessionReplay();
      },
      mountTerminal(s) {
        const el = this.$refs.termEl;
        if (!el || typeof window.Terminal === "undefined") { this.ptyErr = "terminal not available"; return; }
        this._destroyTerm();
        const term = new window.Terminal({
          cursorBlink: true, fontSize: 13, scrollback: 5000,
          fontFamily: "ui-monospace, Menlo, Consolas, monospace",
          theme: { background: "#0f172a", foreground: "#e2e8f0" },
          cols: s.cols || 80, rows: s.rows || 24,
        });
        term.open(el);
        this._term = term;
        window.__partoutTerm = term; // debug/test hook (read terminal buffer headlessly)
        term.onData((d) => this._sendInput(d));
        term.onResize(({ cols, rows }) => {
          this.api("/sessions/" + encodeURIComponent(this.p1) + "/resize", { method: "POST", body: { cols, rows }, silent: true }).catch(() => {});
        });
        // Replay chunks that arrived before the terminal mounted (the initial
        // shell prompt usually precedes the mount).
        const key = s.session_id || s.id || this.p1;
        if (this._liveBuf && this._liveBuf[key]) {
          try { term.write(this._liveBuf[key]); } catch (e) { }
          delete this._liveBuf[key];
        }
        term.focus();
      },
      _sendInput(d) {
        if (!this._term) return;
        const b64 = btoa(unescape(encodeURIComponent(d))); // unicode-safe
        this.api("/sessions/" + encodeURIComponent(this.p1) + "/input", { method: "POST", body: { data_b64: b64 }, silent: true }).catch(() => {});
      },
      _onSessionData(p) {
        if (!p || p.session_id !== this.p1) return;
        if (this._term) { try { if (p.data) this._term.write(atob(p.data)); } catch (e) { } return; }
        // Terminal not mounted yet: buffer recent output (bounded) for catch-up.
        // Decode each chunk now — concatenating base64 strings then atob()ing the
        // joined value is invalid (padding lands mid-string), so the pre-mount
        // prompt would be dropped.
        this._liveBuf = this._liveBuf || {};
        let chunk = "";
        try { chunk = p.data ? atob(p.data) : ""; } catch (e) { chunk = ""; }
        this._liveBuf[this.p1] = (this._liveBuf[this.p1] || "") + chunk;
        if (this._liveBuf[this.p1].length > 512 * 1024) this._liveBuf[this.p1] = this._liveBuf[this.p1].slice(-256 * 1024);
      },
      _termFinalize(p) {
        try { this._term.write("\r\n\x1b[90m[session ended" + (p.exit_code != null ? " (exit " + p.exit_code + ")" : "") + "]\x1b[0m\r\n"); } catch (e) { }
      },
      _destroyTerm() { if (this._term) { try { this._term.dispose(); } catch (e) { } this._term = null; } },
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
        if (!this.fileHost && this.hosts.length) { this.fileHost = this.hosts[0].id; this.loadFileRoot(this.fileHost); }
        if (!this.fileHost) { this.fileEntries = []; return; }
        this.fileLoading = true;
        try { const q = "?agent_id=" + encodeURIComponent(this.fileHost) + "&path=" + encodeURIComponent(this.fileDir || "/"); const d = await this.api("/files/list" + q); this.fileEntries = d.entries || []; }
        catch (e) { this.fileEntries = []; } finally { this.fileLoading = false; }
      },
      async loadJobs() { try { const d = await this.api("/jobs"); this.jobs = d.items || d || []; } catch (e) { this.jobs = []; } },
      async loadTasks() { try { const d = await this.api("/tasks"); this.tasks = d.items || d || []; } catch (e) { this.tasks = []; } },
      openTaskForm() { this.taskForm = { name: "", description: "", steps: [{}] }; this.taskFormOpen = true; },
      addTaskStep() { this.taskForm.steps.push({ kind: "command", name: "", command: "", args: "", path: "", content: "", mode: "0644", package: "", state: "installed", service: "" }); },
      async saveTask() {
        const f = this.taskForm;
        if (!f.name || !f.steps.length) return;
        // Map the form step shape to the API TaskStep shape (drop empties).
        const steps = f.steps.map(s => {
          const st = { kind: s.kind };
          if (s.name) st.name = s.name;
          if (s.kind === "command") { st.command = s.command || ""; const a = (s.args||"").split(/\s+/).filter(Boolean); if (a.length) st.args = a; }
          if (s.kind === "file") { st.path = s.path || ""; st.content = s.content || ""; if (s.mode) st.mode = s.mode; }
          if (s.kind === "package") { st.package = s.package || ""; st.state = s.state || "installed"; }
          if (s.kind === "service") { st.service = s.service || ""; st.state = s.state || "running"; }
          return st;
        });
        this.taskCreateBusy = true;
        try {
          await this.api("/tasks", { body: { name: f.name, description: f.description, steps } });
          this.notify("ok", "task \"" + f.name + "\" created");
          this.taskFormOpen = false; this.taskForm = { name: "", description: "", steps: [] };
          this.loadTasks();
        } catch (e) { /* toast shown by api() */ } finally { this.taskCreateBusy = false; }
      },
      async loadPlaybooks() { try { const d = await this.api("/playbooks"); this.playbooks = d.items || d || []; } catch (e) { this.playbooks = []; } },
      async loadUpdates() {
        // /packages/updates is per-host and REQUIRES agent_id; there is no
        // fleet-wide endpoint. Default to the first host when none is chosen.
        if (!this.updHost && this.hosts.length) this.updHost = this.hosts[0].id;
        if (!this.updHost) { this.updates = []; return; }
        this.pkgChecked = {}; // row selections are per-host; a host switch or refresh starts clean
        try { const d = await this.api("/packages/updates?agent_id=" + encodeURIComponent(this.updHost)); this.updates = d.items || d || []; } catch (e) { this.updates = []; }
        this.loadSecurity();
      },
      // --- Security (M5.1 periodic CVE scan) ---
      async loadSecurity() {
        try { const d = await this.api("/security", { toast: false }); this.security = d.items || []; } catch (e) { this.security = []; }
      },
      async scanSecurity() {
        this.secBusy = true;
        try {
          const d = await this.api("/security/scan", { method: "POST", body: {} });
          this.notify("ok", "security scan: " + (d.scanned != null ? d.scanned + " host(s) scanned" : "done"));
          await this.loadSecurity();
        } catch (e) { /* toast shown by api() */ } finally { this.secBusy = false; }
      },
      secTop(s) { return (s.findings || [])[0]; },
      secCountBadge(s) {
        const t = this.secTop(s);
        if (!t) return "neutral";
        if (t.max_cvss >= 9) return "bad";
        if (t.max_cvss >= 7) return "warn";
        return "neutral";
      },
      // --- Releases (M8.1 update store) ---
      async loadReleases() {
        try { const d = await this.api("/updates/releases"); this.releases = d.items || []; } catch (e) { this.releases = []; }
      },
      onRelFile(ev) {
        const f = ev.target.files[0];
        if (!f) { this.relForm.file = null; return; }
        this.relForm.file = f.name;
        const rd = new FileReader();
        rd.onload = () => {
          const dataUrl = String(rd.result);
          this.relForm.fileB64 = dataUrl.slice(dataUrl.indexOf(",") + 1);
        };
        rd.readAsDataURL(f);
      },
      async uploadRelease() {
        this.relBusy = true;
        try {
          const version = this.relForm.version;
          await this.api("/updates/releases", { method: "POST", body: {
            version: this.relForm.version, arch: this.relForm.arch, kind: this.relForm.kind,
            signature: this.relForm.signature, artifact_b64: this.relForm.fileB64,
          }});
          this.notify("ok", "release " + version + " uploaded");
          this.relForm = { version: "", arch: "linux-amd64", kind: "agent", signature: "", file: null, fileB64: "" };
          await this.loadReleases();
        } catch (e) { /* toast shown by api() */ } finally { this.relBusy = false; }
      },
      async deleteRelease(r) {
        if (!await this.askConfirm({ title: "Delete release", body: "This removes the release artifact from the store. Hosts that already applied it are unaffected.", mono: r.version + " (" + r.arch + ", " + r.kind + ")", confirmLabel: "Delete release", variant: "danger", requireText: r.version })) return;
        try {
          await this.api("/updates/releases/" + encodeURIComponent(r.id), { method: "DELETE" });
          this.notify("ok", "release deleted");
          this.loadReleases();
        } catch (e) { /* toast shown by api() */ }
      },
      runStatusKind(st) {
        if (st === "verified" || st === "completed") return "ok";
        if (st === "failed" || st === "failed_rollback" || st === "aborted") return "bad";
        if (st === "skipped" || st === "timed_out" || st === "pending" || st === "draft") return "warn";
        if (st === "queued" || st === "canary" || st === "rolling" || st === "paused_failure" || st === "dispatching" || st === "restarting") return "info";
        return "neutral";
      },
      runTerminal(st) { return ["completed", "failed", "aborted"].includes(st); },
      async loadRuns() {
        try {
          const d = await this.api("/updates/runs");
          this.runs = d.items || [];
        } catch (e) { this.runs = []; }
      },
      async openRun(id) {
        this.runDetailId = id;
        try {
          const d = await this.api("/updates/runs/" + encodeURIComponent(id));
          this.runDetail = d;
          const run = this.runs.find(r => r.id === id);
          if (run && d.run) { run.status = d.run.status; run.done_hosts = d.run.done_hosts; run.failed_hosts = d.run.failed_hosts; run.skipped_hosts = d.run.skipped_hosts; }
        } catch (e) { /* toast shown by api() */ }
      },
      async createRun() {
        this.runBusy = true; this.runNotice = "";
        try {
          const d = await this.api("/updates/runs", { body: {
            release_id: this.runForm.release_id, selector: this.runForm.selector,
            canary: this.runForm.canary || 0, wave_pct: this.runForm.wave || 25,
          } });
          this.runNotice = d.state === "pending_approval"
            ? "Run " + d.run_id + " parked on approval " + d.approval_id + " — approve it in Approvals to start."
            : "Run " + d.run_id + " started (" + d.state + ").";
          this.notify("ok", this.runNotice);
          await this.loadRuns();
          this.openRun(d.run_id);
        } catch (e) { /* toast shown by api() */ } finally { this.runBusy = false; }
      },
      async startDraft(id) {
        this.runBusy = true;
        try {
          await this.api("/updates/runs/" + encodeURIComponent(id) + "/start", { body: {} });
          this.notify("ok", "run " + id + ": rollout started");
          await this.loadRuns();
          this.openRun(id);
        } catch (e) { /* toast shown by api() */ } finally { this.runBusy = false; }
      },
      async runAction(action) {
        if (!this.runDetail) return;
        const id = this.runDetail.run.id;
        this.runBusy = true;
        try {
          await this.api("/updates/runs/" + encodeURIComponent(id) + "/" + action, { body: {} });
          this.notify("ok", "run " + id + ": " + action + " applied");
          await this.loadRuns();
          this.openRun(id);
        } catch (e) { /* toast shown by api() */ } finally { this.runBusy = false; }
      },
      async loadSecrets() { try { const d = await this.api("/secrets"); this.secrets = d.secrets || d.items || []; } catch (e) { this.secrets = []; } },
      async loadPolicies() { try { const d = await this.api("/policies"); this.policies = d.items || d || []; } catch (e) { this.policies = []; } },
      async loadPreset() { try { this.presetStatus = await this.api("/preset"); } catch (e) { this.presetStatus = null; } },
      async applyPreset() { try { const r = await this.api("/preset/apply", { method: "POST", body: {} }); this.notify("ok", "preset applied: " + (r.created_policies?.length || 0) + " policy, " + (r.created_alerts?.length || 0) + " alert rule default(s)"); this.loadPolicies(); this.loadPreset(); } catch (e) { } },
      async loadProvRuns() { try { const d = await this.api("/provision-runs"); this.provRuns = d.items || []; } catch (e) { this.provRuns = []; } if (!this.hosts.length) this.loadHosts(); },
      provTerminal(state) { return ["connected", "failed", "cancelled", "handoff"].includes(state); },
      // provOnce de-dupes per-run terminal toasts (the server can emit the
      // same terminal event twice, e.g. provision.connected from the state
      // machine + the enroll watcher). Returns true once per (kind, run) per
      // 4 s window.
      provOnce(kind, runId) {
        const key = kind + ":" + (runId || "");
        const now = Date.now();
        if (now - (this._provOnce[key] || 0) < 4000) return false;
        this._provOnce[key] = now;
        for (const k of Object.keys(this._provOnce)) if (now - this._provOnce[k] > 60000) delete this._provOnce[k];
        return true;
      },
      async showProvRun(id) {
        if (this.provDetail && this.provDetail.run && this.provDetail.run.id === id) { this.provDetail = null; return; }
        await this.loadProvDetail(id);
      },
      async loadProvDetail(id) {
        try { this.provDetail = await this.api("/provision-runs/" + encodeURIComponent(id)); }
        catch (e) { this.provDetail = null; }
      },
      async createProvRun() {
        this.provMsg = ""; this.provBusy = true;
        try {
          const d = await this.api("/provision-runs", { method: "POST", body: { host: this.provHost, mode: this.provMode } });
          this.provMsg = "Provisioning run " + (d.id || "") + " started on " + this.provHost + " (state " + (d.state || "") + ").";
          this.notify("ok", "provision run started");
          this.provHost = "";
          this.loadProvRuns();
        } catch (e) { this.provMsg = "Provision failed: " + e.message; } finally { this.provBusy = false; }
      },
      // --- Onboarding wizard (guided SSH provisioning) ---
      openProvWizard() {
        // Starting a fresh wizard detaches any previous watch; the earlier
        // run keeps going server-side and stays visible in the Runs table.
        this.provWiz = { open: true, phase: "target", host: this.provHost || "", mode: this.provMode || "fresh", runId: "", busy: false, run: null, steps: [], sshStatus: null, sshBusy: false, sshErr: "" };
      },
      dismissGettingStarted() {
        this.gsDismissed = true;
        try { localStorage.setItem("partout.gs.dismissed", "1"); } catch (e) { /* private mode: fine */ }
      },
      // --- Confirmation dialog (replaces native confirm()) ---
      // askConfirm shows the dialog and resolves true/false. opts: { title,
      // body, mono (prominent mono block, e.g. a fingerprint), confirmLabel,
      // variant (danger|primary|ok), requireText (type-to-confirm guard) }.
      askConfirm(opts) {
        const o = Object.assign({ title: "Are you sure?", body: "", mono: "", confirmLabel: "Confirm", variant: "danger", requireText: "" }, opts || {});
        return new Promise((resolve) => {
          this.confirmBox = { open: true, title: o.title, body: o.body, mono: o.mono, confirmLabel: o.confirmLabel, variant: o.variant, requireText: o.requireText, value: "", inputLabel: "", inputPlaceholder: "", inputType: "text", input: "", _resolve: resolve, _isInput: false };
        });
      },
      // askInput: the same shared dialog, but with a free-text (optionally
      // password-typed) input instead of a boolean. Resolves the trimmed
      // input on confirm, null on cancel/Esc — the typed replacement for the
      // remaining native prompt() sites (deny reason, secret rotate value).
      askInput(opts) {
        const o = Object.assign({ title: "Input", body: "", mono: "", confirmLabel: "OK", variant: "primary", inputLabel: "Value", inputPlaceholder: "", inputType: "text", initial: "" }, opts || {});
        return new Promise((resolve) => {
          this.confirmBox = { open: true, title: o.title, body: o.body, mono: o.mono, confirmLabel: o.confirmLabel, variant: o.variant, requireText: "", value: "", inputLabel: o.inputLabel, inputPlaceholder: o.inputPlaceholder, inputType: o.inputType, input: o.initial, _resolve: resolve, _isInput: true };
        });
      },
      confirmBoxYes() {
        const r = this.confirmBox._resolve, isInput = this.confirmBox._isInput;
        const val = (this.confirmBox.input || "").trim();
        this.confirmBox.open = false;
        if (r) r(isInput ? val : true);
      },
      confirmBoxNo() {
        const r = this.confirmBox._resolve, isInput = this.confirmBox._isInput;
        this.confirmBox.open = false;
        if (r) r(isInput ? null : false);
      },
      confirmBoxAllowed() {
        if (!this.confirmBox.requireText) return true;
        return this.confirmBox.value.trim() === this.confirmBox.requireText;
      },
      provWizClose() {
        const inFlight = !!(this.provWiz.runId && this.provWiz.run && !this.provTerminal(this.provWiz.run.state));
        if (!inFlight) {
          this.provWiz.runId = ""; this.provWiz.run = null; this.provWiz.steps = [];
        }
        // In-flight run: the wizard stays attached in the background — the
        // provision.* SSE events keep refreshing it if re-opened (Watch
        // button on the run row) and the terminal SSE toast still fires.
        const hadRun = !!this.provWiz.runId;
        this.provWiz.open = false;
        if (hadRun) this.loadProvRuns();
      },
      // Re-attach the wizard to an existing run from the Runs table.
      async provWizWatch(id) {
        this.provWiz.open = true; this.provWiz.phase = "live"; this.provWiz.runId = id;
        this.provWiz.run = null; this.provWiz.steps = [];
        // Event-driven live view: the initial fetch plus the provision.* SSE
        // events for this run (onSSEEvent) — no polling interval.
        await this.provWizRefresh();
      },
      provWizNext() {
        if (this.provWiz.phase === "target" && this.provWiz.host.trim()) {
          this.provWiz.phase = "confirm";
          this.provWizLoadSSH();
        }
      },
      // Fetch the identity-key readiness report so the confirm screen can show
      // the operator exactly which key will be used (or that none was found)
      // BEFORE a run can fail on a missing key.
      async provWizLoadSSH() {
        this.provWiz.sshBusy = true; this.provWiz.sshErr = "";
        try {
          this.provWiz.sshStatus = await this.api("/provision/ssh-status", { toast: false });
        } catch (e) {
          this.provWiz.sshStatus = null; this.provWiz.sshErr = e.message;
        } finally { this.provWiz.sshBusy = false; }
      },
      async provWizStart() {
        this.provWiz.busy = true;
        try {
          const d = await this.api("/provision-runs", { method: "POST", body: { host: this.provWiz.host.trim(), mode: this.provWiz.mode } });
          this.provWiz.runId = d.id;
          this.provWiz.phase = "live";
          // Event-driven from here: the provision.* SSE events for this run
          // trigger provWizRefresh (onSSEEvent) — no polling interval. The
          // initial refresh below paints the run as it was created; every
          // subsequent step/key/terminal event refetches it.
          await this.provWizRefresh();
        } catch (e) { this.notify("err", "provision start failed: " + e.message); } finally { this.provWiz.busy = false; }
      },
      async provWizRefresh() {
        if (!this.provWiz.runId) return;
        try {
          const d = await this.api("/provision-runs/" + encodeURIComponent(this.provWiz.runId), { toast: false });
          this.provWiz.run = d.run; this.provWiz.steps = d.steps || [];
        } catch (e) { /* keep last state on a transient error */ }
      },
      async provWizKey(action) {
        try { await this.api("/provision-runs/" + encodeURIComponent(this.provWiz.runId) + "/key", { method: "POST", body: { action } }); await this.provWizRefresh(); } catch (e) { this.notify("err", e.message); }
      },
      async provWizCancel() {
        if (!await this.askConfirm({ title: "Cancel provisioning", body: "The run is stopped; any partial state on the host is left as-is.", confirmLabel: "Cancel run", variant: "danger" })) return;
        try { await this.api("/provision-runs/" + encodeURIComponent(this.provWiz.runId) + "/cancel", { method: "POST" }); await this.provWizRefresh(); } catch (e) { this.notify("err", e.message); }
      },
      provWizOpenHost() {
        const id = this.provWiz.run && this.provWiz.run.agent_id;
        this.provWizClose();
        if (id) this.go("host/" + id);
      },
      async decideProvKey(id, action) {
        const run = this.provRuns.find(r => r.id === id);
        const fp = (run && run.fingerprint) || "";
        if (action === "confirm") {
          if (!await this.askConfirm({ title: "Confirm host key", body: "The run will resume and install the agent on " + (run ? run.host : id) + ". Verify this fingerprint out-of-band.", mono: fp, confirmLabel: "Confirm key", variant: "ok" })) return;
        } else {
          if (!await this.askConfirm({ title: "Deny host key", body: "The run will be cancelled. Use this if the fingerprint does not match the host you intended to provision.", confirmLabel: "Deny key", variant: "danger" })) return;
        }
        try { await this.api("/provision-runs/" + encodeURIComponent(id) + "/key", { method: "POST", body: { action } }); this.notify("ok", "host key " + action + "d"); this.loadProvRuns(); }
        catch (e) { /* toast shown by api() */ }
      },
      async cancelProvRun(id) {
        if (!await this.askConfirm({ title: "Cancel provision run", body: "The run is stopped; any partial state on the host is left as-is.", mono: id, confirmLabel: "Cancel run", variant: "danger" })) return;
        try { await this.api("/provision-runs/" + encodeURIComponent(id) + "/cancel", { method: "POST" }); this.notify("ok", "provision run cancelled"); this.loadProvRuns(); }
        catch (e) { /* toast shown by api() */ }
      },
      // --- packages: apply + actions (M3) ---
      async loadPkgActions() { try { const d = await this.api("/packages/actions"); this.pkgActions = d.items || d || []; } catch (e) { this.pkgActions = []; } },
      async showPkgAction(id) {
        if (this.pkgActionDetail && this.pkgActionDetail.id === id) { this.pkgActionDetail = null; return; }
        try { this.pkgActionDetail = await this.api("/packages/actions/" + encodeURIComponent(id)); }
        catch (e) { this.pkgActionDetail = null; }
      },
      setPkgChecks(names) { const m = {}; for (const n of names) m[n] = true; this.pkgChecked = m; },
      togglePkgCheck(name, on) { const m = { ...this.pkgChecked }; if (on) m[name] = true; else delete m[name]; this.pkgChecked = m; },
      async applyUpdates() {
        if (!this.updHost) return;
        const checked = Object.keys(this.pkgChecked);
        const typed = this.pkgSel.split(/,\s*/).map(s => s.trim()).filter(Boolean);
        const pkgs = checked.length ? checked : typed;
        let scope;
        if (pkgs.length) {
          scope = (checked.length ? checked.length + " checked package(s)" : typed.length + " package(s)");
          if (pkgs.length <= 5) scope += ": " + pkgs.join(", ");
        } else scope = "ALL pending updates";
        const verb = this.pkgDryRun ? "Dry-run" : "Apply";
        if (!await this.askConfirm({ title: this.pkgDryRun ? "Dry-run apply" : "Apply updates", body: scope + " on " + this.updHost + ". " + (this.pkgDryRun ? "Dry run only — no packages are installed." : "A dry-run is always executed first; the action is policy-gated (pkg.apply)."), confirmLabel: this.pkgDryRun ? "Dry-run" : "Apply", variant: this.pkgDryRun ? "primary" : "danger" })) return;
        this.pkgBusy = true; this.pkgMsg = "";
        try {
          const d = await this.api("/packages/apply", { method: "POST", body: { agent_id: this.updHost, packages: pkgs, dry_run: this.pkgDryRun } });
          if (d.state === "approval_required") {
            this.pkgMsg = "Apply parked on approval " + (d.approval_id || "") + " — an admin must approve it (Approvals page).";
          } else {
            this.pkgMsg = (this.pkgDryRun ? "Dry run " : "Apply ") + "dispatched (action " + (d.id || "") + ", status " + (d.status || "") + ").";
          }
          this.loadPkgActions();
        } catch (e) { this.pkgMsg = "Apply failed: " + e.message; } finally { this.pkgBusy = false; }
      },
      // --- Security patching (fan-out apply over CVE findings) ---
      // Hosts with findings, mapped to {agent_id, packages} targets: the
      // CVE-affected packages per host (deduped).
      secPatchTargets() {
        return (this.security || [])
          .filter(s => (s.findings || []).length)
          .map(s => ({ agent_id: s.agent_id, host: this.hostNameById(s.agent_id), packages: [...new Set((s.findings || []).map(f => f.pkg))] }));
      },
      async patchHostSecurity(s) {
        if ((s.findings || []).length) await this.patchSecurityTargets([s], "Patch security updates on " + this.hostNameById(s.agent_id));
      },
      async patchAllSecurity() {
        await this.patchSecurityTargets(this.security.filter(s => (s.findings || []).length), "Patch security updates on ALL hosts with findings");
      },
      async patchSecurityTargets(hosts, title) {
        const targets = hosts
          .filter(s => (s.findings || []).length)
          .map(s => ({ agent_id: s.agent_id, host: this.hostNameById(s.agent_id), packages: [...new Set((s.findings || []).map(f => f.pkg))] }));
        if (!targets.length) return;
        const detail = targets.map(t => t.host + ": " + t.packages.join(", ")).join(" · ");
        const body = "Applies the CVE-affected packages below (dry-run first; policy-gated per host, can park on approval). " + (detail.length > 400 ? detail.slice(0, 397) + "…" : detail);
        if (!await this.askConfirm({ title, body, confirmLabel: "Patch", variant: "danger" })) return;
        this.secPatchBusy = true; this.pkgMsg = "";
        try {
          const d = await this.api("/packages/apply", { method: "POST", body: { targets: targets.map(t => ({ agent_id: t.agent_id, packages: t.packages })), dry_run: false } });
          // Single target → legacy single result; multi → {results, summary}.
          const results = d.results || [d];
          const appr = results.filter(r => r.state === "approval_required");
          const errs = results.filter(r => r.state === "error");
          const done = results.filter(r => r.state === "ok" || r.state === undefined);
          let msg;
          if (results.length === 1) {
            const r = results[0];
            if (r.state === "approval_required") msg = "Parked on approval " + (r.approval_id || "") + " — an admin must approve it (Approvals page).";
            else if (r.status && r.status !== "succeeded") msg = "Patch failed on " + (r.agent_id || "") + ": " + (r.error || r.status);
            else msg = "Patch dispatched (action " + (r.id || "") + ", status " + (r.status || "") + ").";
          } else {
            msg = results.length + " host(s): " + done.length + " dispatched, " + appr.length + " parked on approval";
            if (errs.length) msg += ", " + errs.length + " failed (" + errs.map(e => this.hostNameById(e.agent_id) + ": " + firstLine(e.error)).join("; ") + ")";
            msg += ".";
          }
          msg += " Run “Scan now” to refresh the findings.";
          this.pkgMsg = msg;
          if (errs.length) this.notify("err", "patch: " + errs.length + " of " + results.length + " host(s) failed", 10000);
          else this.notify("ok", "patch: " + results.length + " host(s) " + (appr.length ? "— " + appr.length + " awaiting approval" : "dispatched"), 8000);
          this.loadPkgActions();
        } catch (e) { this.pkgMsg = "Patch failed: " + e.message; } finally { this.secPatchBusy = false; }
      },
      // --- jobs: CRUD (M3) ---
      async newJobForm() {
        this.jobErr = "";
        this.jobForm = { id: "", name: "", task_id: "", cron: "", selector: "all", enabled: true };
        if (!this.tasks.length) await this.loadTasks();
        if (this.tasks.length === 1) this.jobForm.task_id = this.tasks[0].id;
      },
      editJob(j) {
        this.jobErr = "";
        this.jobForm = { id: j.id, name: j.name, task_id: j.task_id, cron: j.cron, selector: j.selector, enabled: j.enabled };
        if (!this.tasks.length) this.loadTasks();
      },
      async saveJob() {
        const f = this.jobForm;
        if (!f || !f.name || !f.cron || !f.task_id || !f.selector) return;
        this.jobBusy = true; this.jobErr = "";
        const body = { name: f.name, task_id: f.task_id, task_version: 0, cron: f.cron, selector: f.selector, enabled: f.enabled };
        try {
          if (f.id) await this.api("/jobs/" + encodeURIComponent(f.id), { method: "PUT", body });
          else await this.api("/jobs", { body });
          this.jobForm = null;
          this.loadJobs();
          this.notify("ok", "job \"" + f.name + "\" saved");
        } catch (e) { this.jobErr = e.code === "policy_denied" ? "Policy denied: " + e.message : e.message; } finally { this.jobBusy = false; }
      },
      async deleteJob(j) {
        if (!await this.askConfirm({ title: "Delete job", body: "Its scheduled fires stop immediately.", mono: j.name, confirmLabel: "Delete job", variant: "danger" })) return;
        try { await this.api("/jobs/" + encodeURIComponent(j.id), { method: "DELETE" }); this.notify("ok", "job \"" + j.name + "\" deleted"); this.loadJobs(); }
        catch (e) { /* toast shown by api() */ }
      },
      async showJobRuns(id) {
        if (this.jobRunsDetail && this.jobRunsDetail.job_id === id) { this.jobRunsDetail = null; return; }
        await this.loadJobRuns(id);
      },
      async loadJobRuns(id) {
        try { const d = await this.api("/jobs/" + encodeURIComponent(id) + "/runs"); this.jobRunsDetail = { job_id: id, runs: d.items || d || [] }; }
        catch (e) { this.jobRunsDetail = null; }
      },
      async loadUsers() { try { const d = await this.api("/users"); this.users = d.items || d || []; } catch (e) { this.users = []; } },
      async loadMcpClients() { try { const d = await this.api("/mcp/clients", { toast: false }); this.mcpClients = d.clients || d.items || d || []; } catch (e) { this.mcpClients = []; } },
      async loadExtStatus() { try { this.extStatus = await this.api("/external-data/status", { toast: false }); } catch (e) { this.extStatus = null; } },
      async refreshExtData() {
        this.extBusy = true;
        try { const d = await this.api("/external-data/refresh", { method: "POST", body: {} }); this.notify("ok", "EOL data refreshed (" + (d.rows != null ? d.rows + " rows" : "ok") + ")"); await this.loadExtStatus(); }
        catch (e) { /* toast shown by api() */ } finally { this.extBusy = false; }
      },
      async createUser() {
        const f = this.userForm;
        if (!f.username || !f.password) return;
        this.userBusy = true;
        try { await this.api("/users", { body: { username: f.username, password: f.password, role: f.role } }); this.notify("ok", "user \"" + f.username + "\" created"); this.userForm = { username: "", password: "", role: "operator" }; this.loadUsers(); }
        catch (e) { /* toast shown by api() */ } finally { this.userBusy = false; }
      },
      async setUserRole(u, role) {
        const n = u.username || u.name;
        try { await this.api("/users/" + encodeURIComponent(n), { method: "PATCH", body: { role } }); this.notify("ok", "" + n + " role set to " + role); this.loadUsers(); }
        catch (e) { /* toast shown by api() */ this.loadUsers(); } // revert the <select> on a rejected change
      },
      async toggleUserDisabled(u) {
        const n = u.username || u.name;
        if (!await this.askConfirm({ title: (u.disabled ? "Enable" : "Disable") + " user", body: (u.disabled ? "This user regains access." : "This user loses access immediately."), mono: n, confirmLabel: (u.disabled ? "Enable" : "Disable"), variant: u.disabled ? "ok" : "danger" })) return;
        try { await this.api("/users/" + encodeURIComponent(n), { method: "PATCH", body: { disabled: !u.disabled } }); this.notify("ok", "user \"" + n + "\" " + (u.disabled ? "enabled" : "disabled")); this.loadUsers(); }
        catch (e) { /* toast shown by api() */ }
      },
      async loadAlerts() { try { const d = await this.api("/alerts"); this.alerts = d.alerts || []; } catch (e) { this.alerts = []; } },
      async loadRules() { try { const d = await this.api("/alerts/rules"); this.rules = d.rules || []; } catch (e) { this.rules = []; } },
      // --- alert rule management (M7) ---
      thresholdsLabel(r) {
        const t = (r.thresholds && typeof r.thresholds === "object") ? r.thresholds : {};
        const out = [];
        for (const [k, v] of Object.entries(t)) out.push(k + "=" + v);
        return out.length ? out.join(" ") : "—";
      },
      ruleDefaultThresh(kind) { return ({ service_failed: 5, service_restarting: 10, cert_expiring: 30, config_drift: 0, config_invalid: 0, update_drift: 1 })[kind] || 0; },
      newRuleForm() {
        this.ruleErr = "";
        this.ruleForm = { id: "", name: "", kind: "service_failed", selector: "all", severity: "warning", thresh: 5, status: "paused_failure,failed", severityMin: "high", enabled: true };
      },
      editRule(r) {
        this.ruleErr = "";
        const t = (r.thresholds && typeof r.thresholds === "object") ? r.thresholds : {};
        const key = ({ service_failed: "service_failed_minutes", service_restarting: "service_restart_rate_per_hour", cert_expiring: "cert_days_remaining", config_drift: "config_drift_tolerance", update_drift: "min_drifted" })[r.kind];
        this.ruleForm = {
          id: r.id, name: r.name, kind: r.kind, selector: r.selector,
          severity: r.severity, enabled: r.enabled,
          thresh: (key && t[key] != null) ? t[key] : this.ruleDefaultThresh(r.kind),
          status: (t.status != null) ? t.status : "paused_failure,failed",
          severityMin: (t.min_severity != null) ? t.min_severity : "high",
        };
      },
      thresholdsFor(kind) {
        const v = this.ruleForm.thresh;
        switch (kind) {
          case "service_failed": return { service_failed_minutes: v };
          case "service_restarting": return { service_restart_rate_per_hour: v };
          case "cert_expiring": return { cert_days_remaining: v };
          case "config_drift": return { config_drift_tolerance: v };
          case "update_run": return { status: (this.ruleForm && this.ruleForm.status) || "paused_failure,failed" };
          case "update_drift": return { min_drifted: v || 1 };
          case "security_updates": return { min_severity: (this.ruleForm && this.ruleForm.severityMin) || "high", min_count: v || 1 };
          default: return {};
        }
      },
      async saveRule() {
        const f = this.ruleForm;
        if (!f || !f.name) return;
        this.ruleBusy = f.id || "new"; this.ruleErr = "";
        const body = { name: f.name, kind: f.kind, selector: f.selector || "all", severity: f.severity, enabled: f.enabled, thresholds: this.thresholdsFor(f.kind) };
        try {
          if (f.id) await this.api("/alerts/rules/" + encodeURIComponent(f.id), { method: "PUT", body });
          else await this.api("/alerts/rules", { body });
          this.ruleForm = null;
          this.loadRules();
          this.notify("ok", "rule \"" + f.name + "\" saved");
        } catch (e) { this.ruleErr = e.message; } finally { this.ruleBusy = ""; }
      },
      async toggleRule(r) {
        this.ruleBusy = r.id; this.ruleErr = "";
        try {
          await this.api("/alerts/rules/" + encodeURIComponent(r.id), { method: "PUT", body: { name: r.name, kind: r.kind, selector: r.selector, severity: r.severity, enabled: !r.enabled, thresholds: r.thresholds || {} } });
          this.loadRules();
        } catch (e) { this.ruleErr = e.message; } finally { this.ruleBusy = ""; }
      },
      async deleteRule(id) {
        if (!await this.askConfirm({ title: "Delete alert rule", body: "Firing alerts from it are left as-is.", mono: id, confirmLabel: "Delete rule", variant: "danger" })) return;
        try { await this.api("/alerts/rules/" + encodeURIComponent(id), { method: "DELETE" }); this.notify("ok", "rule deleted"); this.loadRules(); }
        catch (e) { /* toast shown by api() */ }
      },
      // --- task actions (M7): run task / playbook + run inspection ---
      async runTask(t) {
        if (!this.hosts.length) { this.notify("info", "No hosts available to run this task on."); return; }
        const agent = this.hosts.length === 1 ? this.hosts[0].id
          : prompt("Run task " + t.name + " on which host?\n" + this.hosts.map(h => h.id).join("\n"), this.hosts[0].id);
        if (!agent) return;
        this.taskBusy = t.id; this.taskMsg = "";
        this.taskNote[t.id] = { kind: "info", text: "Dispatching on " + agent + "…" };
        try {
          const d = await this.api("/tasks/" + encodeURIComponent(t.id) + "/run", { method: "POST", body: { agent_id: agent } });
          // Row-level outcome (the roadmap's dispatch-progress-on-the-row);
          // the page-level taskMsg is kept for the runs table context.
          if (d.state === "approval_required") {
            this.taskNote[t.id] = { kind: "info", text: "Parked on approval " + (d.approval_id || "") + " — an admin must approve it (Approvals page)." };
          } else {
            this.taskNote[t.id] = { kind: "info", text: "Started on " + agent + " (run " + (d.run_id || "?") + ", state " + (d.state || "?") + ")." };
          }
          this.loadTaskRuns();
        } catch (e) { this.taskNote[t.id] = { kind: "err", text: e.message }; } finally { this.taskBusy = ""; }
      },
      async runPlaybook(p) {
        this.taskBusy = p.id; this.taskMsg = "";
        this.taskNote[p.id] = { kind: "info", text: "Dispatching across " + (p.selector || "its selector") + "…" };
        try {
          const d = await this.api("/playbooks/" + encodeURIComponent(p.id) + "/run", { method: "POST", body: {} });
          const runs = (d.runs || []).map(r => r.agent_id + "=" + r.state).join(", ");
          const errs = (d.errors || []).join("; ");
          this.taskNote[p.id] = { kind: errs ? "err" : "info", text: "Playbook " + p.name + ": " + (runs || "no matching hosts") + (errs ? " · errors: " + errs : "") };
          this.loadTaskRuns();
        } catch (e) { this.taskNote[p.id] = { kind: "err", text: e.message }; } finally { this.taskBusy = ""; }
      },
      async loadTaskRuns() { try { const d = await this.api("/tasks/runs"); this.taskRuns = d.items || d || []; } catch (e) { this.taskRuns = []; } },
      async showTaskRun(id) {
        if (this.taskRunDetail && this.taskRunDetail.id === id) { this.taskRunDetail = null; return; }
        try { this.taskRunDetail = await this.api("/tasks/runs/" + encodeURIComponent(id)); }
        catch (e) { this.taskRunDetail = null; }
      },
      async loadApprovals() { this.apprMsg = ""; const q = this.apprState ? "?state=" + encodeURIComponent(this.apprState) : ""; try { const d = await this.api("/approvals" + q); this.approvals = d.approvals || []; } catch (e) { this.approvals = []; } },
      async loadMcp() { try { this.mcpInfo = await this.api("/mcp/info"); } catch (e) { this.mcpInfo = null; } },
      protocolHost() { return location.protocol + '//' + location.host; },
      mcpSnippet() {
        if (!this.mcpInfo) return '';
        const cmd = (this.mcpInfo.stdio_command || '').replace('<bearer>', '<your token>');
        // stdio command line from the server-rendered template, split on first space.
        const parts = cmd.split(/\s+/);
        return JSON.stringify({ mcpServers: { partout: { command: parts[0], args: parts.slice(1) } } }, null, 2);
      },
      async decideApproval(id, verb) {
        // Approve is a write to a host: confirm; deny takes an optional reason.
        if (verb === "approve") {
          if (!await this.askConfirm({ title: "Approve " + id, body: "The exact stored payload will be dispatched to the agent.", confirmLabel: "Approve", variant: "ok" })) return;
        } else {
          // Typed in the shared dialog, not a native prompt(): the reason is
          // recorded on the audit trail and shown to the requester.
          const r = await this.askInput({ title: "Deny " + id, body: "The parked action is denied and finalized; the reason is recorded on the audit trail.", confirmLabel: "Deny", variant: "danger", inputLabel: "Reason (optional)", inputPlaceholder: "why this action was refused" });
          if (r === null) return;
          this._denyReason = r;
        }
        this.apprBusy = id; this.apprMsg = "";
        try {
          const body = verb === "deny" && this._denyReason ? { reason: this._denyReason } : {};
          await this.api("/approvals/" + encodeURIComponent(id) + "/" + verb, { method: "POST", body });
          this.loadApprovals();
        } catch (e) {
          this.apprMsg = (verb === "approve" ? "Approve" : "Deny") + " failed: " + e.message;
        } finally { this.apprBusy = ""; }
      },
      // --- observe pages: filters + cross-links (M7) ---
      // Prefill page filters from the hash-route query (cross-link targets
      // like obs/certs?host=ag_x&q=/etc/ssl/app.pem).
      syncObserveQuery() {
        const q = this.routeQuery;
        if (this.page === "obs-services") {
          if (q.host) this.svcF.host = q.host;
          if (q.name) this.svcF.unit = q.name;
        } else if (this.page === "obs-certs") {
          if (q.host) this.certHost = q.host;
          if (q.q) this.certQ = q.q;
        } else if (this.page === "obs-configs") {
          if (q.host) this.cfgHost = q.host;
          if (q.kind) this.cfgKind = q.kind;
        }
      },
      // A haproxy/nginx unit links to its config on the same host.
      unitCfgLink(row) {
        const n = row.unit.name;
        return (n === "haproxy" || n === "nginx") ? "obs/configs?host=" + row.host_id + "&kind=" + n : "";
      },
      // Configs referencing this cert's path (listeners' TLS / vhost ssl_certificate),
      // plus agent-side service-config discovery labels (caddy, and paths the
      // topology parsers didn't capture).
      certUsedBy(row) {
        const out = [];
        const path = row.cert.path;
        if (!path) return out;
        for (const c of this.certsConfigs) {
          if (c.host_id !== row.host_id) continue;
          if (c.haproxy) for (const l of (c.haproxy.listeners || [])) if (l.tls === path) out.push({ kind: "haproxy", label: ":" + l.port, link: true });
          if (c.nginx) for (const v of (c.nginx.vhosts || [])) if (v.tls_cert === path) out.push({ kind: "nginx", label: v.server_name || "vhost", link: true });
        }
        for (const lb of (row.cert.labels || [])) {
          if (!out.some(u => u.kind === lb)) out.push({ kind: lb, label: "config", link: false });
        }
        return out;
      },
      async loadServices() { try { const d = await this.api("/services"); this.services = d.items || []; this.svcDetail = null; } catch (e) { this.services = []; } },
      svcKey(row) { return row.host_id + "/" + row.unit.name; },
      toggleSvcDetail(key) { this.svcDetail = this.svcDetail === key ? null : key; },
      svcClearF() { this.svcF = { unit: "", host: "", state: "", enabled: "", exit: "", restart: "", label: "" }; },
      async svcCopySel() {
        const sel = this.svcTarget;
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(sel); }
          else throw new Error("no clipboard API");
          this.notify("ok", "selector copied: " + sel);
        } catch (e) {
          const ta = document.createElement("textarea");
          ta.value = sel; ta.style.position = "fixed"; ta.style.opacity = "0";
          document.body.appendChild(ta); ta.select();
          let ok = false;
          try { ok = document.execCommand("copy"); } catch (e2) { ok = false; }
          document.body.removeChild(ta);
          if (ok) this.notify("ok", "selector copied: " + sel);
          else this.notify("err", "copy failed — the selector is: " + sel, 8000);
        }
      },
      svcNewAlert() {
        // Suggest the rule kind that matches what the filter shows: a
        // failed-state view maps to service_failed; an active view to
        // service_restarting (watch the running ones for restart loops).
        const kind = this.svcF.state === "active" ? "service_restarting" : "service_failed";
        this.alertPrefill = { selector: this.svcTarget, kind };
        this.go("obs-alerts");
      },
      async svcSaveGroup() {
        const name = (this.svcGroupName || "").trim();
        if (!name) return;
        this.svcGroupBusy = true;
        try {
          await this.api("/groups", { body: { name, selector: this.svcTarget } });
          this.notify("ok", "group \"" + name + "\" saved — selector: group:" + name);
          this.svcGroupName = "";
        } catch (e) { /* toast shown by api() */ } finally { this.svcGroupBusy = false; }
      },
      // last-run verdict for the Exit column: systemd's Result= word plus the
      // exit code when numeric. "success"/absent (never run or still up) and
      // clean stops render as a dash rather than noise.
      unitExit(u) {
        const r = u.result || "";
        if (!r || r === "success") return "—";
        return r + (u.last_exit_code ? " (" + u.last_exit_code + ")" : "");
      },
      // Loopback hostnames (the local-dev posture): localhost + its subdomains
      // (RFC 6761 reserves *.localhost), the loopback IPs, and an empty host
      // (file:// or a bare host). Anything else on http: is a cleartext path.
      isLoopbackHost(h) {
        const s = String(h || "").toLowerCase();
        if (s === "" || s === "localhost" || s === "127.0.0.1" || s === "::1" || s === "[::1]") return true;
        return s.endsWith(".localhost");
      },
      // config_error text when the validator failed ("" when valid/unknown).
      cfgErr(c) { const x = c.haproxy || c.nginx; return (x && !x.config_valid && x.config_error) ? x.config_error : ""; },
      // Config badge state. A root-only config (config_readable === false) is
      // NOT necessarily invalid — the agent just cannot see it; say so (warn)
      // instead of mislabeling a healthy service. Older agents omit the
      // field entirely: legacy valid/invalid behavior.
      cfgState(c) {
        const x = c.haproxy || c.nginx;
        if (!x) return { t: "—", cls: "neutral", title: "" };
        if (x.config_readable === false) {
          if (x.config_valid) return { t: "valid (elevated)", cls: "ok", title: "validated via an authorized elevation; the file itself is root-only" };
          return { t: "not readable", cls: "warn", title: "config file is root-only (the partout user cannot read it) — not necessarily invalid. Add an elevation policy rule (e.g. 'haproxy' + args ['-c','-f',cfg] and a 'cat' grant) then: sudo partout ctl elevation install-sudoers — or grant read access." };
        }
        return x.config_valid
          ? { t: "valid", cls: "ok", title: x.config_file || "" }
          : { t: "invalid", cls: "bad", title: this.cfgErr(c) || x.config_file || "" };
      },
      async loadCerts() {
        try {
          const d = await this.api("/certificates" + buildQ({ agent_id: this.certHost, days_remaining_lt: this.certDays }));
          let items = d.items || [];
          if (this.certQ) {
            const q = this.certQ.toLowerCase();
            items = items.filter(r => ((r.cert.subject || "").toLowerCase().includes(q) || (r.cert.path || "").toLowerCase().includes(q)));
          }
          this.certs = items;
        } catch (e) { this.certs = []; }
        // Unfiltered config inventory for the "Used by" cross-links.
        try { const d = await this.api("/configs"); this.certsConfigs = d.items || []; } catch (e) { this.certsConfigs = []; }
      },
      async loadConfigs() { try { const d = await this.api("/configs" + buildQ({ agent_id: this.cfgHost, kind: this.cfgKind })); this.configs = d.items || []; } catch (e) { this.configs = []; } },
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
        try { const d = await this.api("/executions", { body }); const id = d.execution_id || d.id; this.exCmd = ""; this.preview = null; if (id) { this.notify("ok", "command dispatched"); this.go("exec/" + id); } }
        catch (e) { /* toast shown by api() */ }
      },
      async cancelExec(id) { try { await this.api("/executions/" + encodeURIComponent(id) + "/cancel", { method: "POST" }); this.notify("ok", "execution cancelled"); this.loadExecDetail(); } catch (e) { /* toast shown by api() */ } },
      async runJob(job) {
        // POST /jobs/{id}/run requires an explicit agent_id.
        if (!this.hosts.length) { this.notify("info", "No hosts available to run this job on."); return; }
        const agent = this.hosts.length === 1 ? this.hosts[0].id : prompt("Run on which host?\n" + this.hosts.map(h => h.id).join("\n"), this.hosts[0].id);
        if (!agent) return;
        this.jobRunBusy = job.id; this.jobErr = "";
        this.jobNote[job.id] = { kind: "info", text: "Dispatching on " + agent + "…" };
        try {
          const d = await this.api("/jobs/" + encodeURIComponent(job.id) + "/run", { method: "POST", body: { agent_id: agent } });
          // Row-level outcome: the note under the affected row is the primary
          // feedback (the roadmap's "dispatch progress on the row").
          if (d && d.state === "approval_required") this.jobNote[job.id] = { kind: "info", text: "Run parked on approval " + (d.approval_id || "") + " — an admin must approve it (Approvals page)." };
          else this.jobNote[job.id] = { kind: "info", text: "Run started on " + agent + " (run " + ((d && d.run_id) || "?") + ", state " + ((d && d.state) || "?") + ")." };
        } catch (e) { this.jobNote[job.id] = { kind: "err", text: e.message }; } finally { this.jobRunBusy = ""; }
      },
      dismissNote(map, id) { delete map[id]; },
      // Body-ported tooltip for overflow-hidden truncated cells (ui-guidelines
      // §23): the CSS ::after tooltip is clipped by the very cell it decorates,
      // so those sites carry data-jtip and this single floating element shows
      // the full text on hover AND keyboard focus. Delegated listeners, one
      // element, no per-cell wiring.
      initJTip() {
        if (this._jtipEl || typeof document === "undefined") return;
        const el = document.createElement("div");
        el.className = "jtip"; el.setAttribute("role", "tooltip");
        document.body.appendChild(el);
        this._jtipEl = el;
        const show = (target) => {
          const txt = target.getAttribute("data-jtip");
          if (!txt) { el.classList.remove("show"); return; }
          el.textContent = txt;
          el.classList.add("show");
          el.style.left = "0px"; el.style.top = "0px"; // reset before measuring
          const r = target.getBoundingClientRect();
          const w = el.offsetWidth, h = el.offsetHeight;
          // Below the cell, clamped into the viewport; above it when no room.
          let left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8));
          let top = r.bottom + 7;
          if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 7);
          el.style.left = left + "px"; el.style.top = top + "px";
        };
        const hide = () => el.classList.remove("show");
        this._jtipHide = hide;
        document.addEventListener("mouseover", (e) => {
          const t = e.target && e.target.closest ? e.target.closest("[data-jtip]") : null;
          if (t) show(t); else if (!(e.target && e.target.closest && e.target.closest(".jtip"))) hide();
        });
        document.addEventListener("mouseout", (e) => {
          const t = e.target && e.target.closest ? e.target.closest("[data-jtip]") : null;
          if (t) hide();
        });
        document.addEventListener("focusin", (e) => {
          const t = e.target && e.target.closest ? e.target.closest("[data-jtip]") : null;
          if (t) show(t); else hide();
        });
        document.addEventListener("focusout", hide);
        document.addEventListener("scroll", hide, true);
      },
      openFile(f) { if (f.is_dir) { this.fileDir = joinPath(this.fileDir, f.name); this.listFiles(); } },
      async downloadFile(f) {
        const path = joinPath(this.fileDir, f.name);
        try {
          const res = await fetch("/api/v1/files/download?agent_id=" + encodeURIComponent(this.fileHost) + "&path=" + encodeURIComponent(path), { headers: { Authorization: "Bearer " + this.token } });
          if (!res.ok) { this.notify("err", "download failed: " + res.status); return; }
          const blob = await res.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = f.name; document.body.appendChild(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 4000);
        } catch (e) { this.notify("err", "download failed: " + e.message); }
      },
      fileUp() { this.fileDir = parentPath(this.fileDir); this.listFiles(); },
      pickFileHost(id) { this.fileHost = id; this.fileDir = "/"; this.fileRoot = ""; this.listFiles(); this.loadFileRoot(id); },
      // Load the selected host's file root fact (docs/spec-file-root.md).
      async loadFileRoot(id) { try { const d = await this.api("/hosts/" + encodeURIComponent(id) + "/facts", { toast: false }); this.fileRoot = (d.facts && d.facts["partout.file_root"]) || ""; } catch (e) { this.fileRoot = ""; } },
      // ---- File dialog: view / edit-CAS / perm (M2 API was ahead of the UI) ----
      openFileDlg(f) {
        const path = joinPath(this.fileDir, f.name);
        this.fileDlg = { open: true, host: this.fileHost, path, name: f.name, loading: true, busy: false, permBusy: false, stat: null, content: "", origSha: "", err: "", binary: false, tooLarge: false, mode: "", owner: "", group: "", dirty: false };
        this.fileDlgLoad();
      },
      async fileDlgLoad() {
        const d = this.fileDlg;
        if (!d) return;
        d.loading = true; d.err = ""; d.dirty = false;
        try {
          const st = await this.api("/files/stat?agent_id=" + encodeURIComponent(d.host) + "&path=" + encodeURIComponent(d.path), { toast: false });
          d.stat = st; d.origSha = st.sha256 || ""; d.mode = st.mode || ""; d.owner = st.owner || ""; d.group = st.group || "";
          d.tooLarge = (st.size || 0) > 1024 * 1024;
          if (!d.tooLarge && !st.is_dir) {
            const res = await fetch("/api/v1/files/download?agent_id=" + encodeURIComponent(d.host) + "&path=" + encodeURIComponent(d.path), { headers: { Authorization: "Bearer " + this.token } });
            if (!res.ok) throw new Error("read failed (HTTP " + res.status + ")");
            const buf = new Uint8Array(await res.arrayBuffer());
            let binary = false;
            const probe = buf.slice(0, 8192);
            for (let i = 0; i < probe.length; i++) if (probe[i] === 0) { binary = true; break; }
            d.content = new TextDecoder("utf-8").decode(buf);
            if (d.content.indexOf("\uFFFD") !== -1) binary = true; // replacement chars → not text
            d.binary = binary;
          }
        } catch (e) { d.err = e.message; d.stat = d.stat || { size: 0, mode: "", owner: "", group: "" }; }
        d.loading = false;
      },
      fileDlgReload() { this.fileDlgLoad(); },
      async fileDlgSave() {
        const d = this.fileDlg;
        if (!d.origSha) { d.err = "No baseline sha256 — Reload the file, then Save."; return; }
        if (!await this.askConfirm({ title: "Save file (CAS)", body: "Writes " + d.content.length + " bytes to " + d.path + " on " + this.hostNameById(d.host) + ". Policy-gated (file.write) and audited. Aborts if the file changed since you opened it.", confirmLabel: "Save", variant: "danger" })) return;
        d.busy = true; d.err = "";
        try {
          const r = await this.api("/files/edit", { method: "POST", body: { agent_id: d.host, path: d.path, expected_sha256: d.origSha, content_b64: b64FromBytes(new TextEncoder().encode(d.content)) } });
          d.origSha = r.sha256 || ""; d.dirty = false;
          if (d.stat) d.stat.size = d.content.length;
          this.notify("ok", "saved " + d.name + " (sha256 " + (d.origSha || "").slice(0, 8) + "…)");
        } catch (e) {
          if (e.status === 409) {
            d.err = "Conflict: the file changed on the host since you opened it. Reload to pick up the new content, then re-apply your change.";
            this.notify("err", "save rejected: file changed since you opened it (CAS)", 10000);
          } else d.err = "Save failed: " + e.message;
        } finally { d.busy = false; }
      },
      async fileDlgPerm() {
        const d = this.fileDlg;
        const what = [d.mode && "mode " + d.mode, d.owner && "owner " + d.owner, d.group && "group " + d.group].filter(Boolean).join(", ");
        if (!what) return;
        if (!await this.askConfirm({ title: "Apply permissions", body: "Set " + what + " on " + d.path + " (policy-gated file.perm, audited). Blank fields are left unchanged.", confirmLabel: "Apply", variant: "danger" })) return;
        d.permBusy = true;
        try {
          await this.api("/files/perm", { method: "POST", body: { agent_id: d.host, path: d.path, mode: d.mode, owner: d.owner, group: d.group } });
          this.notify("ok", "permissions updated on " + d.path);
        } catch (e) { this.notify("err", "perm failed: " + e.message); } finally { d.permBusy = false; }
      },
      // ---- File upload ----
      openUpDlg() {
        if (!this.fileHost) return;
        this.upDlg = { open: true, file: null, path: "", mode: "0644", busy: false, err: "" };
      },
      upDlgFilePicked(ev) {
        const f = ev.target.files && ev.target.files[0];
        if (!f) return;
        this.upDlg.file = f;
        if (!this.upDlg.path.trim()) this.upDlg.path = joinPath(this.fileDir, f.name);
      },
      async upDlgGo() {
        const u = this.upDlg; const f = u.file;
        if (!f || !u.path.trim()) return;
        if (f.size > 256 * 1024 * 1024) { u.err = "File exceeds the 256 MiB server cap."; return; }
        if (!await this.askConfirm({ title: "Upload file", body: f.name + " (" + fmtBytes(f.size) + ") → " + u.path.trim() + " on " + this.hostNameById(this.fileHost) + ". Overwrites any existing file at that path. Policy-gated (file.write), audited.", confirmLabel: "Upload", variant: "danger" })) return;
        u.busy = true; u.err = "";
        try {
          const buf = new Uint8Array(await f.arrayBuffer());
          const r = await this.api("/files/upload", { method: "POST", body: { agent_id: this.fileHost, path: u.path.trim(), content_b64: b64FromBytes(buf), mode: u.mode } });
          this.notify("ok", "uploaded " + u.path.trim() + " (sha256 " + ((r.sha256 || "").slice(0, 8)) + "…)");
          u.open = false;
          this.listFiles();
        } catch (e) { u.err = "Upload failed: " + e.message; } finally { u.busy = false; }
      },
      // ---- Add-host dialog (Fleet) ------------------------------------
      openAddHost() {
        if (!this.isOperator) return;
        this.addHostOpen = true;
        this.addHostTab = "manual";
        this.startAhTicker();
      },
      closeAddHost() {
        this.addHostOpen = false;
        this.ahToken = null;
        this.ahTokenExpiry = 0;
        this.stopAhTicker();
      },
      startAhTicker() { this.stopAhTicker(); this.ahTickInt = setInterval(() => { this.ahNow = Date.now(); }, 1000); },
      stopAhTicker() { if (this.ahTickInt) { clearInterval(this.ahTickInt); this.ahTickInt = null; } },
      async mintAddHostToken() {
        if (!this.isOperator) return;
        this.ahTokenBusy = true;
        try {
          const d = await this.api("/agents/enrollment-tokens", { body: { ttl_s: 900 } });
          this.ahToken = d.token; this.ahTokenExpiry = d.expires;
          this.notify("ok", "enrollment token created — shown once, 15 min TTL");
        } catch (e) { /* toast shown by api() */ } finally { this.ahTokenBusy = false; }
      },
      async copyAhCmd() {
        try { await navigator.clipboard.writeText(this.ahCmd); this.notify("ok", "copied to clipboard"); }
        catch (e) { this.notify("err", "copy failed — select the text manually"); }
      },
      async createGroup() {
        const name = prompt("Group name:"); if (!name) return;
        const selector = prompt("Selector (all | host:ag_x | group:db):", "all"); if (!selector) return;
        try { await this.api("/groups", { body: { name, selector } }); this.notify("ok", "group \"" + name + "\" created"); this.loadGroups(); } catch (e) { /* toast shown by api() */ }
      },
      async deleteSecret(n) { if (await this.askConfirm({ title: "Delete secret", body: "Hosts referencing this secret must be updated.", mono: n, confirmLabel: "Delete secret", variant: "danger", requireText: n })) { try { await this.api("/secrets/" + encodeURIComponent(n), { method: "DELETE" }); this.notify("ok", "secret deleted"); this.loadSecrets(); } catch (e) { /* toast shown by api() */ } } },
      async createSecret() {
        const f = this.secretForm;
        if (!f.name || !f.value) return;
        this.secretBusy = true;
        try { await this.api("/secrets", { body: { name: f.name, value: f.value, selector: f.selector || "all" } }); this.notify("ok", "secret \"" + f.name + "\" created"); this.secretForm = { name: "", value: "", selector: "all" }; this.loadSecrets(); }
        catch (e) { /* toast shown by api() */ } finally { this.secretBusy = false; }
      },
      async rotateSecret(name) {
        // The new value is typed into the shared dialog with password
        // masking — a native prompt() echoed the secret in cleartext.
        const v = await this.askInput({ title: "Rotate secret " + name, body: "A new version is created; all prior versions are revoked. The value is never displayed again.", confirmLabel: "Rotate", variant: "primary", inputLabel: "New value", inputType: "password", inputPlaceholder: "the new secret value" });
        if (v === null || v === "") return;
        try { const d = await this.api("/secrets/" + encodeURIComponent(name) + "/rotate", { method: "POST", body: { value: v } }); this.notify("ok", "secret \"" + name + "\" rotated (v" + (d.version != null ? d.version : "") + ")"); this.loadSecrets(); }
        catch (e) { /* toast shown by api() */ }
      },
      async deletePolicy(id) { if (await this.askConfirm({ title: "Delete policy", body: "This removes the policy; matching actions are no longer governed by it.", mono: id, confirmLabel: "Delete policy", variant: "danger" })) { try { await this.api("/policies/" + encodeURIComponent(id), { method: "DELETE" }); this.notify("ok", "policy deleted"); this.loadPolicies(); } catch (e) { /* toast shown by api() */ } } },
      async deleteUser(n) { if (await this.askConfirm({ title: "Delete user", body: "The user can no longer sign in.", mono: n, confirmLabel: "Delete user", variant: "danger", requireText: n })) { try { await this.api("/users/" + encodeURIComponent(n), { method: "DELETE" }); this.notify("ok", "user deleted"); this.loadUsers(); } catch (e) { /* toast shown by api() */ } } },
    },
    created() {
      window.addEventListener("hashchange", () => { this.route = (location.hash || "#/fleet").replace(/^#\/?/, ""); });
    },
    mounted() {
      if (typeof window !== "undefined") window.__partout = this; // test hook: component instance
      // Capture how this page was actually served: cleartextLogin warns on
      // the login card when the operator is about to send a password over an
      // unencrypted network path (same condition doctor warns on server-side).
      this.locProtocol = (typeof location !== "undefined" && location.protocol) || "";
      this.locHostname = (typeof location !== "undefined" && location.hostname) || "";
      this.initJTip();
      this.loadNavCollapsed();
      window.addEventListener("keydown", this.onGlobalKey);
      if (this.token) {
        Promise.all([this.refreshCaps(), this.loadMe(), this.loadGroups(), this.loadVersion()]).then(() => {
          // A 401 already went through sessionExpired (token cleared, toast,
          // return route kept) — don't sign out again and wipe the slot. Only
          // a still-held token (e.g. server unreachable on load) takes the
          // plain sign-out path.
          if (!this.me) { if (this.token) this.signOut(); return; }
          this.ensureNavExpanded();
          this.startSSE(); this.loadPageData(); this.loadNavBadges();
        });
      }
    },
    beforeUnmount() { this.stopSSE(); this.stopAhTicker(); window.removeEventListener("keydown", this.onGlobalKey); },
    watch: {
      page() { if (this.page !== "session") this._destroyTerm(); this.ensureNavExpanded(); this.loadPageData(); },
      p1() { if (["host", "exec", "session"].includes(this.page)) this.loadPageData(); },
      paletteQ() { this.paletteIdx = 0; },
      // Same-page query change (cross-link, e.g. obs/certs → obs/certs?host=x):
      // the page/p1 watchers don't fire, so re-sync filters and reload.
      route(nv, ov) {
        const pageOf = (s) => {
          const p = String(s || "").split("?")[0].split("/").filter(Boolean);
          return p[0] === "obs" ? "obs-" + (p[1] || "services") : (p[0] || "fleet");
        };
        const np = pageOf(nv), op = pageOf(ov);
        if (np !== op || !np.startsWith("obs-")) return;
        this.loadPageData();
      },
    },
  });

  app.config.errorHandler = (err) => { console.error("partout ui:", err); };
  // Test hook: expose the app so the headless smoke harness can drive it.
  if (typeof window !== "undefined") window.__partout = app;
  app.mount("#app");
})();
