package elevate

// ExplainResult is the policy-only answer to "does this command elevate,
// and why" (the elevation-policy legibility slice, P3.3). It carries the
// matched rule (and its index into the policy) so a caller can highlight
// exactly the line in the editor that produced the verdict — the same
// vocabulary the agent's run rows use, without needing an agent.
type ExplainResult struct {
	// Elevated reports whether (name, args) matches a rule.
	Elevated bool `json:"elevated"`
	// Note is the human-readable reason (mirrors PolicyRunner.Explain).
	Note string `json:"note"`
	// RuleIndex is the matched rule's index, or -1 when none matched.
	RuleIndex int `json:"rule_index"`
	// Rule is the matched rule (zero value when none matched).
	Rule Rule `json:"rule,omitempty"`
	// Tier is the policy's privilege tier (strict/broad/full).
	Tier string `json:"tier"`
}

// Explain answers, for a loaded policy and one (name, args) pair, whether
// the command elevates and which rule says so. It reuses the policy's own
// matcher (Check/RuleFor) so the verdict here is the verdict the host's
// agent would reach — the note format mirrors PolicyRunner.Explain. A nil
// policy is the no-policy case: nothing elevates.
func Explain(pol *Policy, name string, args []string) ExplainResult {
	if pol == nil {
		return ExplainResult{
			Elevated:  false,
			Note:      "no elevation policy loaded — nothing elevates",
			RuleIndex: -1,
			Tier:      "",
		}
	}
	res := ExplainResult{Tier: pol.Tier(), RuleIndex: -1}
	if pol.Check(name, args) == Elevated {
		if i, r := ruleAt(pol, name, args); i >= 0 {
			res.Elevated, res.RuleIndex, res.Rule = true, i, *r
			res.Note = "policy rule matched: " + describeRule(r)
			return res
		}
	}
	res.Note = "no elevation rule matches this command — it would run unprivileged (add a rule to the elevation policy to elevate it)"
	return res
}

// ruleAt returns the first rule matching (name, args) with its index.
func ruleAt(pol *Policy, name string, args []string) (int, *Rule) {
	if pol == nil {
		return -1, nil
	}
	for i := range pol.Rules {
		if pol.Rules[i].matches(name, args) {
			r := pol.Rules[i]
			return i, &r
		}
	}
	return -1, nil
}
