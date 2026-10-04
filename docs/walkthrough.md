# Operator walkthrough — the perceived-quality instrument (beta)

Five operators, one moderator, one hour each, three scripted tasks. This is
the only quality instrument that measures what users *experience* rather
than what the code does — run it before every beta tag (ux-improvements
§8). No telemetry exists by design (offline-capable product), so this is
where "perceived quality" is actually observed.

## Setup (moderator)

- A clean test server (fresh install, empty fleet), the operator's own
  laptop, a browser they did not configure. **Do not touch their mouse.**
- One throwaway managed host they may provision over SSH.
- Screen + audio recording with consent; hesitations matter more than
  success.

## Script

Introduce only this, verbatim:

> "This is Partout — a fleet management tool. Here's the login. I'd like
> you to onboard your first host, run a command on the fleet, and react to
> a problem. Please think out loud — say what you expect to happen before
> you click."

### Task A — onboard the first host (fresh install → first value)

Observe: does the Setup checklist appear and read as actionable? Do they
find "Start onboarding"? Where do they hesitate — SSH credentials, the
one-time token, the host-key gate? Does any message lie to them ("not in
this build", "legacy agent")?

### Task B — run a command and confirm it (the core loop)

Ask for: `uptime` on the host they onboarded, then prove it happened in
the audit log. Observe: the first-command nudge, output rendering, the
trail audit → execution. Then ask them to request the same thing via the
**Assistant** (if configured): does the run land in the same places with
the same attribution (feedback parity)?

### Task C — react to a firing alert (the observe half)

Pre-seed: one firing alert rule (e.g. a service down or disk threshold)
before the session. Observe: do they find it (nav badge? Alerts page?),
does the detail explain *what and where*, can they get from the alert to
the host in one click? Present the remediation affordance honestly.

## Capture sheet (per operator, per task)

| Field | Notes |
|---|---|
| Operator background (ops / dev / both) | |
| Task completed without help? (yes / hint / rescue) | |
| First hesitation — what were they looking for? | |
| Message that was wrong, vague, or missing (quote it) | |
| Wrong assumption made (and what led them there) | |
| Time to first success | |
| One thing they'd tell a friend about the product | |
| One thing that almost made them give up | |

## Scoring (beta exit criteria)

- Every task completes without rescue for ≥4/5 operators.
- Zero **lies** quoted (a message claiming something untrue — the
  "legacy agent" / "approval required" / "disabled in this build" class).
- Every quoted vague/missing message becomes a filed issue with the
  session timestamp.
- Moderator logs each class of finding: truthful?, findable?,
  attributable?, recoverable? — matching the four quality axes.
