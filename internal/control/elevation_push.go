// Control — server-signed elevation policy push (P2).
//
// "Push policy to fleet": resolve the stored policy, sign it with the
// server identity key (the same key that signs policy Decisions — agents
// already pin its public half), and dispatch a governed ElevationPush to
// each selected host. The agent applies it through its own sudoers
// self-grant (the root context re-verifies the signature), so the wall
// stays host-owned: nothing widens on the host that the host's current
// sudoers does not already allow.
package control

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/store"
)

// PushElevationPolicy pushes a stored elevation policy to the hosts a
// selector resolves. Every host is gated by the deny-list policy engine
// (action class elevation.push — require_approval parks the push for that
// host exactly like any other write); connected hosts apply immediately,
// offline hosts are refused loudly (a privilege-document push must not
// silently queue — the offline TTL window could outlive the operator's
// intent).
func (c *Control) PushElevationPolicy(policyName, selector, actor, actorRole string) (pushed, skipped []PushHostResult, err error) {
	if c.ident == nil {
		return nil, nil, errors.New("control: no server identity (cannot sign the push)")
	}
	p, err := c.st.ElevationPolicy(policyName)
	if err != nil {
		return nil, nil, fmt.Errorf("elevation policy %q: %w", policyName, err)
	}
	// Canonicalize (the agent verifies the sha of the canonical marshal —
	// a hand-formatted stored document would otherwise be rejected).
	pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + p.RulesJSON + `}`))
	if err != nil {
		return nil, nil, fmt.Errorf("elevation policy %q invalid: %w", policyName, err)
	}
	canonical := marshalRulesCanonical(pol)
	pushID := id.New("epp")
	sig := policy.SignElevationPush(c.ident.Priv, pushID, p.Name, pol.PolicyHash())
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	resolver := store.NewResolver(c.st)
	infos, err := resolver.ResolveSelector(selector)
	if err != nil {
		return nil, nil, err
	}

	rules, _ := c.st.GetPolicyRules()
	for _, hi := range infos {
		res := PushHostResult{AgentID: hi.ID}
		dec := policy.Evaluate(rules, policy.Action{
			ActionClass: policy.ActionElevationPush,
			HostID:      hi.ID,
			ActorRole:   actorRole,
		})
		switch dec.Effect {
		case policy.EffectDeny:
			res.State = "denied"
			res.Detail = "policy: " + strings.Join(dec.MatchedRules, ",")
			skipped = append(skipped, res)
			c.audit("elevation.push.denied", actor, map[string]string{
				"push_id": pushID, "agent_id": hi.ID, "policy": p.Name, "rules": strings.Join(dec.MatchedRules, ","),
			})
			continue
		case policy.EffectRequireApproval:
			// Fail closed and loud: parking a privilege-document push
			// behind an approval that may never come (then expiring) is
			// worse than refusing — the operator adjusts the rule or
			// approves an explicit re-push.
			res.State = "denied"
			res.Detail = "policy requires approval (elevation.push) — approve-adjust the rule or re-push after approval"
			skipped = append(skipped, res)
			c.audit("elevation.push.approval_required", actor, map[string]string{
				"push_id": pushID, "agent_id": hi.ID, "policy": p.Name, "rules": strings.Join(dec.MatchedRules, ","),
			})
			continue
		}
		push := &pb.ElevationPush{
			PushId:     pushID,
			PolicyName: p.Name,
			RulesJson:  canonical,
			PolicySha:  pol.PolicyHash(),
			Signature:  sigB64,
		}
		if err := c.h.SendElevationPush(hi.ID, push); err != nil {
			if errors.Is(err, stream.ErrAgentOffline) {
				res.State = "refused"
				res.Detail = "host is offline — a privilege-document push is never queued (re-push when connected)"
			} else {
				res.State = "failed"
				res.Detail = err.Error()
			}
			skipped = append(skipped, res)
			continue
		}
		res.State = "pushed"
		res.Detail = "policy " + p.Name + " (sha " + pol.PolicyHash()[:12] + ") signed + dispatched"
		pushed = append(pushed, res)
		c.audit("elevation.push.dispatched", actor, map[string]string{
			"push_id": pushID, "agent_id": hi.ID, "policy": p.Name, "policy_sha12": pol.PolicyHash()[:12],
		})
	}
	sort.Slice(pushed, func(i, j int) bool { return pushed[i].AgentID < pushed[j].AgentID })
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].AgentID < skipped[j].AgentID })
	return pushed, skipped, nil
}

// PushHostResult is one host's dispatch outcome.
type PushHostResult struct {
	AgentID string `json:"agent_id"`
	State   string `json:"state"` // pushed | denied | refused | failed
	Detail  string `json:"detail,omitempty"`
}

// marshalRulesCanonical renders the canonical compact rules JSON (the
// agent's sha gate covers exactly these bytes).
func marshalRulesCanonical(p *elevate.Policy) string {
	b, _ := json.Marshal(p.Rules)
	return string(b)
}
