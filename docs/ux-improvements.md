# Partout — Web UI UX evaluation & improvement plan

**Status:** research / roadmap — **nothing in this document is implemented yet.** This is a
heuristic evaluation of the shipped UI (v0.9.6+) with ranked recommendations: quick wins for
the near term, larger areas for later versions. As items ship, their sections here get the
✅ treatment (roadmap convention) and the guards move to
[ui-guidelines.md](ui-guidelines.md).
**Companion docs:** [ui-guidelines.md](ui-guidelines.md) (the UI definition — IA, tokens,
components, state vocabulary), [getting-started.md](getting-started.md) (the flow this
evaluation starts from), [roadmap.md](roadmap.md) (milestone plan).

---

## 1. Method and scope

- **Method:** heuristic evaluation against Nielsen's 10 usability heuristics, WCAG 2.1 AA,
  and operator-tool patterns, performed as a single-evaluator review with full code access
  (`internal/api/webui/` — app.js, style.css — plus ui-guidelines as the stated intent).
  Every finding cites verified code, not assumptions.
- **Scope:** the shipped SPA (19 pages, buildless Vue 3 single component, ~3.8k lines
  app.js), the buildless/embedded constraints (no CDN, no build step, offline-capable), and
  the persona floor (operator tool, ~1280px, fleet of tens).
- **Limitations, stated honestly:** there is **no behavioral data** — telemetry is a
  non-goal by design, so nothing here is observed user behavior. It is expert review. The
  cheapest complement (§8) is a scripted moderated walkthrough; findings below should be
  confirmed or killed against it before the big items get scheduled.

## 2. What already follows best practice — keep and protect

These are ahead of most tools in this space and must not regress as the UI grows:

| Practice | Where it lives |
|---|---|
| **Visibility of system status** | SSE stale-banner + dimmed tables, live/reconnecting chips, row spinners, inline dispatch notes (row-level feedback), loading-vs-empty distinction with actionable empty states |
| **Error prevention** | dry-run-first package apply, type-to-confirm on destructive actions, server-authoritative selector preview before any dispatch, capability-gated controls that never look clickable when unavailable |
| **Honest safety model** | policy denials render structured (matched rule + what would satisfy it), distinct from failures; `denied` / `failed` / `not_delivered` visuals are load-bearing |
| **Session trust** | expiry explained (toast + return route), not a silent drop |
| **Accessibility floor** | keyboard operation of rows/tabs/nav with focus rings, tooltips on keyboard focus, `prefers-reduced-motion`, no color-only state, `aria-live` toasts, dark mode with OS default |
| **Operator register** | compact density, monospace for machine text, command palette (⌘K) |

## 3. Findings by heuristic

Severity = frequency × impact for the operator persona. Evidence cites app.js line numbers
at the time of writing (they drift; the mechanism descriptions are the durable part).

### H3 · User control & freedom — medium

- **No undo** for destructive actions (policy/job/secret/user deletes). Mitigated by
  type-to-confirm; acceptable for now, revisit as "soft delete" (§5.6).
- **Recent executions cannot be re-run** — rows navigate to detail only
  (`@click="go('exec/'+e.id)"`); the operator retypes the command. Recall where recognition
  would do (→ quick win Q4).
- **Filter state is not URL-persisted** except the cross-link query params
  (`#/obs/certs?host=…`); refreshing or sharing a filtered view loses it on most pages.

### H4 · Consistency & standards — low/medium

- **Native `prompt()`s remain** in three flows: the job and task "run on which host?"
  pickers (app.js ~3312, ~3516) and group-create's two prompts (name + selector, ~3738).
  The deny-reason and secret-rotate prompts were already replaced by the shared typed
  dialog; these are the remainder (→ quick win Q7).
- Feedback is deliberately tri-modal (global toast / row note / page message) — documented
  in ui-guidelines §10 and consistent so far; watch it as surfaces multiply.

### H5 · Error prevention — medium (weakest form area)

- **Cron is a raw text field with only a placeholder** (`placeholder="0 3 * * *"`): no
  inline syntax validation, no "next runs" preview; mistakes surface only at submit (→
  later item L4).
- Task `when`-guards are likewise free-text with no field-level validation.
- Positive: required-field gating via disabled buttons is consistent across create forms.

### H6 · Recognition rather than recall — medium/high (largest cognitive-load gap)

- Selector, cron, and `when` are all **operator-remembered grammars**. The Execute selector
  has a placeholder and the (excellent, safe) preview button, but no autocomplete and no
  cheat-sheet — even though the completion data (hosts, groups, roles) is already
  client-side (→ quick win Q3).
- **No in-app path to the documentation at all**: `docs/getting-started.md` exists but is
  linked only from the README (→ quick win Q6).

### H7 · Flexibility & efficiency — low/medium

- Command palette is good; shortcuts have no discoverability affordance (no `?` help).
- No bulk actions except the Updates checkbox selection; no saved views / filter presets.
- **The Audit page has no pagination and only a kind filter** — `loadAudit()` fetches one
  page with `?kind=` only, while the API already supports `actor`, `since`, and cursor
  paging. On a real fleet the audit view **silently truncates** (→ quick win Q5).

### H8 · Accessibility beyond the keyboard floor — medium

- **`--text-faint: #94a3b8` on white ≈ 2.6–3.0:1 — fails WCAG AA (4.5:1)** — and it is
  used for *meaningful* metadata (host ids, captions, table metadata), not decoration
  (→ quick win Q1).
- **No focus management in modals**: dialogs do not move focus on open, do not trap Tab
  (background content stays reachable), and do not restore focus on close. Verified: only
  the palette input, the login field, and the terminal ever call `.focus()`. Esc works on
  the confirm dialog only (→ quick win Q2).
- Tables lack `scope`/captions; overlays lack `role="dialog"` / `aria-modal`.

### IA · Host-centric workflow fragmentation — high value, later

Host detail is **Overview + Facts only**; the planned workbench tabs (Terminal · Files ·
Updates · Audit, ui-guidelines §5) never shipped. Files and the terminal live on separate
pages with their own host pickers — during an incident on one host the operator re-selects
the same host four times across four pages (→ later item L1).

### Performance at scale — low today, structural

One Vue component re-renders the entire template per state change; tables are not
virtualized. Fine at the documented fleet scale (tens of hosts); big audit/output views
will jank (→ later item L5, and the modularization L7 that sits under it).

## 4. Quick wins (≤ ~1 day each, ranked by value/effort)

| # | Win | Effort | Notes |
|---|---|---|---|
| Q1 | ~~**Contrast fix**~~ ✅ **shipped**: light `--text-faint` `#94a3b8`→`#64748b` (≈4.75:1 on white), dark `#64748b`→`#94a3b8` (≈6.6:1 on slate-900) — both themes now pass AA for the meaningful text faint carries; pinned by `TestUIShape_ContrastTokens` | hours | One token pair + a shape test; fixed a real WCAG AA failure |
| Q2 | **Modal focus basics**: focus the first control on open (confirm/input/add-host/wizard), Esc closes every dialog, focus returns to the opener; a full Tab-trap is ~20 more lines — do both | ~½ day | Largest a11y gain per line; `askConfirm`/`askInput` already centralize the plumbing |
| Q3 | ~~**Selector autocomplete + cheat-sheet**~~ ✅ **shipped**: a `<datalist id="selector-suggestions">` fed from live fleet data (all, group:, role:, tag:, host:) attached to every selector input (Execute, job form, rollout form, secrets), plus a self-contained `?` grammar help dialog (selector + cron kinds — offline-capable, no CDN) | ~½ day | Verified by the smoke harness (datalist options from live data, help opens/closes with grammar content) |
| Q4 | ~~**Re-run from Recent executions**~~ ✅ **shipped**: a ↻ Re-run button on execution rows prefills the Execute form (cmd/args/selector/timeout) — the first-command-nudge pattern (prefill, never auto-run) | hours | Smoke-verified against the seeded execution: prefilled values + "nothing auto-executed" |
| Q5 | **Audit pagination + actor/time filters**: send `actor`/`since`, add "Load more" via `next_cursor` — the API already supports all of it | ~½ day | The UI silently truncates today |
| Q6 | ~~**Docs links in-app**~~ ✅ **shipped**: "Docs ↗" in the user menu (repo docs, new tab); the grammar help dialog (Q3) covers the cron/selector field hints self-contained and offline. The `when` help lands with a when-field in the task form (none exists yet) | hours | The walkthrough exists; now the product points at it |
| Q7 | **Replace the remaining `prompt()`s** (job/task host picker, group create) with the shared dialog + a host `<select>` | ~½ day | Closes the H4 consistency finding; `askInput` exists to extend |

## 5. Later-version areas (ranked by UX value)

1. **Host workbench consolidation** — bring Terminal / Files / Updates / Audit tabs onto
   the host page (the ui-guidelines §5 plan). Biggest workflow win, especially for incident
   contexts. Depends on L7 or app.js grows badly.
2. **Time-series visualization (uPlot, vendored like xterm.js)** — cert-expiry timelines,
   restart-rate trends, resource history. `host_facts` history already exists server-side;
   observe is tables-only today, which is the single biggest *information* gap for the
   "observe" half of the product. Must respect the no-build-step constraint (vendor the
   runtime, offline-capable).
3. **Real diffs (ui-guidelines B5)** — package dry-run renders a `dry_summary` string; file
   CAS edit is a plain textarea. Diff views are the honest-rendering principle applied to
   change preview: `DiffView` is already specified in ui-guidelines §8 and was never built.
4. **Field-level validation with server parsing** — a "next 3 runs" preview endpoint for
   cron (the robfig parser is already in the binary) and inline `when` validation at task
   save. Turns submit-time failures into typing-time feedback.
5. **Table ergonomics at scale** — column sorting, virtualization for audit/output, and
   URL-persisted filters everywhere (deep-linkable views; the cross-link machinery
   already exists).
6. **Undo / soft-delete for destructive actions** — a retention window for
   policies/jobs/secrets/users instead of permanent delete. Type-to-confirm is
   *prevention*; this is *recovery*. Bigger design decision, operator demand first.
7. **`app.js` modularization** — split the single component into per-page ES modules
   (still buildless, still no Node in `go build`). The enabler for L1–L5; the 276-check
   smoke harness is the safety net for the refactor. Schedule it before the next round of
   UI feature work, not after.
8. **Full WCAG AA audit pass** — labels/roles sweep, focus order, screen-reader
   walkthrough (Q1–Q2 cover the worst of it; decision 17 in ui-guidelines already states
   the honest remaining scope).

## 6. Anti-patterns to avoid as the UI grows

- **Do not hide density behind progressive disclosure** — extra clicks on common paths is
  the wrong trade for an operator tool.
- **Do not replace live SSE views with polling** for implementation simplicity; the
  stale-banner pattern is a differentiator (and the "no polling" invariant is now
  app-wide).
- **Do not auto-execute anything from a "helpful" affordance** — the first-command nudge's
  prefill-then-Run pattern is the model.
- **Do not add decorative dashboards** (gauges, carousels) — every pixel should be
  actionable state.

## 7. Relationship to existing plans

- **ui-guidelines.md is the definition; this doc is the gap analysis.** Where they overlap
  (DiffView, host tabs, active-alerts card), this doc defers to ui-guidelines as the spec
  and adds only priority and evidence.
- Quick wins Q1–Q7 are sized to land as ordinary polish commits (the same shape as the
  v0.9.6+ onboarding work); nothing here changes the milestone plan in roadmap.md. L7
  (modularization) is already flagged there as the pre-1.0 structural item.
- Later items L1/L2/L3 overlap roadmap backlog entries (host workbench tabs were §5's plan;
  uPlot was deferred at R12) — scheduling them is a roadmap decision, not a new scope
  commitment.

## 8. Validation complement (before the big items)

With no telemetry, the cheapest honest check on these findings is a **5-operator moderated
walkthrough** of three scripted tasks — (a) onboard a host, (b) run a command and confirm it
in the audit log, (c) react to a firing alert — noting hesitation points, especially on the
grammars (H6), host switching (IA finding), and modal interactions (H8). Confirm or kill the
H6 and host-fragmentation priorities against observed behavior before scheduling L1/L3.
The repo already runs scripted-human-flavored dogfooding (`writes-e2e.py`,
`ui-smoke.sh`); this is the same discipline with real operators.
