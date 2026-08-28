package authzen

import (
	"context"
	"errors"
	"path"
	"strings"
)

// PDP is an AuthZEN Policy Decision Point.
type PDP interface {
	Evaluate(ctx context.Context, req EvaluationRequest) (EvaluationResponse, error)
}

// PolicyRule defines a single allow, deny, or pending (AARP) policy entry evaluated by InMemoryPDP.
// String fields support glob patterns (path.Match syntax): * matches any sequence of characters.
//
// Evaluation semantics:
//   - Higher Priority wins; ties resolved by position (later index wins).
//   - No matching rule → default deny.
//   - Pending=true overrides Decision — access is denied but can be requested for approval (AARP).
type PolicyRule struct {
	SubjectType  string `json:"subject_type"`          // exact match or "*"
	SubjectID    string `json:"subject_id"`            // glob pattern or "*"
	ResourceType string `json:"resource_type"`         // exact match or "*"
	ResourceID   string `json:"resource_id"`           // glob pattern or "*"
	ActionName   string `json:"action_name"`           // glob pattern or "*"
	Decision     bool   `json:"decision"`              // true = allow, false = explicit deny
	Priority     int    `json:"priority"`              // higher wins; default 0
	Label        string `json:"label,omitempty"`       // human-readable description

	// AARP 1.0: when Pending is true, access is denied but requestable.
	// Decision is ignored — the outcome is always "deny, but can request".
	Pending          bool   `json:"pending,omitempty"`
	ApprovalEndpoint string `json:"approval_endpoint,omitempty"`

	// Obligations Profile 1.0: mandatory PEP actions attached to an ALLOW decision.
	Obligations []Obligation `json:"obligations,omitempty"`
}

// MatchedRule is returned by EvaluateWithReason to explain which rule fired.
type MatchedRule struct {
	Index int
	Rule  PolicyRule
}

// InMemoryPDP is an AuthZEN PDP backed by an ordered slice of PolicyRules.
// Default-deny: if no rule matches, decision is false.
type InMemoryPDP struct {
	rules []PolicyRule
}

// NewInMemoryPDP creates an InMemoryPDP with the given rules.
func NewInMemoryPDP(rules []PolicyRule) *InMemoryPDP {
	return &InMemoryPDP{rules: rules}
}

// AddRule appends a rule.
func (p *InMemoryPDP) AddRule(r PolicyRule) { p.rules = append(p.rules, r) }

// Rules returns a snapshot copy of the current rule slice.
func (p *InMemoryPDP) Rules() []PolicyRule {
	out := make([]PolicyRule, len(p.rules))
	copy(out, p.rules)
	return out
}

// RemoveRule removes the rule at index i.
func (p *InMemoryPDP) RemoveRule(i int) error {
	if i < 0 || i >= len(p.rules) {
		return errors.New("rule index out of range")
	}
	p.rules = append(p.rules[:i], p.rules[i+1:]...)
	return nil
}

// ClearRules removes all rules.
func (p *InMemoryPDP) ClearRules() { p.rules = nil }

// Evaluate finds the highest-priority matching rule and returns its decision.
// AARP: if the matching rule has Pending=true, Decision is false and Pending/ApprovalEndpoint are set.
// Obligations: if the matching rule has Obligations, they are attached to ALLOW responses.
func (p *InMemoryPDP) Evaluate(_ context.Context, req EvaluationRequest) (EvaluationResponse, error) {
	matched, _ := p.findMatch(req)
	return ruleToResponse(matched), nil
}

// EvaluateWithReason returns the decision plus which rule matched (nil if default deny).
func (p *InMemoryPDP) EvaluateWithReason(req EvaluationRequest) (EvaluationResponse, *MatchedRule) {
	matched, idx := p.findMatch(req)
	return ruleToResponse(matched), func() *MatchedRule {
		if matched == nil {
			return nil
		}
		return &MatchedRule{Index: idx, Rule: *matched}
	}()
}

// ruleToResponse converts a matched PolicyRule (or nil for default-deny) to an EvaluationResponse.
func ruleToResponse(matched *PolicyRule) EvaluationResponse {
	if matched == nil {
		return EvaluationResponse{Decision: false}
	}
	// AARP: pending overrides allow/deny — access is denied but can be requested.
	if matched.Pending {
		return EvaluationResponse{
			Decision:         false,
			Pending:          true,
			ApprovalEndpoint: matched.ApprovalEndpoint,
		}
	}
	// Obligations: attach to ALLOW decisions only.
	var obs []Obligation
	if matched.Decision && len(matched.Obligations) > 0 {
		obs = matched.Obligations
	}
	return EvaluationResponse{Decision: matched.Decision, Obligations: obs}
}

func (p *InMemoryPDP) findMatch(req EvaluationRequest) (*PolicyRule, int) {
	best := -1
	bestPri := -1
	for i, r := range p.rules {
		if !ruleMatches(r, req) {
			continue
		}
		if r.Priority > bestPri || (r.Priority == bestPri && i > best) {
			best = i
			bestPri = r.Priority
		}
	}
	if best == -1 {
		return nil, -1
	}
	r := p.rules[best]
	return &r, best
}

func ruleMatches(r PolicyRule, req EvaluationRequest) bool {
	return matchField(r.SubjectType, req.Subject.Type) &&
		matchGlob(r.SubjectID, req.Subject.ID) &&
		matchField(r.ResourceType, req.Resource.Type) &&
		matchGlob(r.ResourceID, req.Resource.ID) &&
		matchGlob(r.ActionName, req.Action.Name)
}

// matchField matches an exact type field; "*" is a wildcard.
func matchField(pattern, value string) bool {
	return pattern == "*" || strings.EqualFold(pattern, value)
}

// matchGlob uses path.Match glob syntax. Empty pattern or "*" always matches.
func matchGlob(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, value)
	return err == nil && matched
}

// DefaultRules returns demo-ready policy rules covering users, SPIFFE workloads,
// and OAuth Token Exchange scenarios.
func DefaultRules() []PolicyRule {
	return []PolicyRule{
		{
			SubjectType: "user", SubjectID: "alice@example.com",
			ResourceType: "document", ResourceID: "*",
			ActionName: "can_read", Decision: true, Priority: 10,
			Label: "alice can read any document",
		},
		{
			SubjectType: "user", SubjectID: "alice@example.com",
			ResourceType: "document", ResourceID: "budget-*",
			ActionName: "can_edit", Decision: true, Priority: 10,
			Label: "alice can edit budget documents",
		},
		{
			SubjectType: "user", SubjectID: "bob@example.com",
			ResourceType: "document", ResourceID: "public-*",
			ActionName: "can_read", Decision: true, Priority: 10,
			Label: "bob can read public documents only",
		},
		{
			SubjectType: "workload", SubjectID: "spiffe://*/admin/*",
			ResourceType: "*", ResourceID: "*",
			ActionName: "*", Decision: true, Priority: 20,
			Label: "admin workloads have full access (SPIFFE glob)",
		},
		{
			SubjectType: "workload", SubjectID: "spiffe://*/agents/orchestrator",
			ResourceType: "token-audience", ResourceID: "*",
			ActionName: "exchange", Decision: true, Priority: 10,
			Label: "orchestrator agent can exchange token for any audience",
		},
		{
			SubjectType: "workload", SubjectID: "spiffe://*/agents/sub-agent",
			ResourceType: "token-audience", ResourceID: "https://api.cloud-b.*",
			ActionName: "exchange", Decision: true, Priority: 10,
			Label: "sub-agent can exchange for cloud-b APIs only",
		},
		{
			SubjectType: "workload", SubjectID: "spiffe://*/agents/*",
			ResourceType: "tool", ResourceID: "search-*",
			ActionName: "invoke", Decision: true, Priority: 5,
			Label: "all agents can invoke search tools",
		},
		// Obligations Profile 1.0: alice can read financial documents, but MUST audit-log.
		{
			SubjectType: "user", SubjectID: "alice@example.com",
			ResourceType: "document", ResourceID: "financial-*",
			ActionName: "can_read", Decision: true, Priority: 15,
			Label: "alice can read financial documents with mandatory audit obligation",
			Obligations: []Obligation{
				{ID: "urn:authzen:obligation:audit-log", Parameters: map[string]string{"level": "high", "retention": "7y"}},
			},
		},
		// AARP 1.0: bob can request access to budget documents (currently denied, but requestable).
		{
			SubjectType: "user", SubjectID: "bob@example.com",
			ResourceType: "document", ResourceID: "budget-*",
			ActionName: "can_read", Pending: true, Priority: 10,
			ApprovalEndpoint: "https://approvals.example.com/request/budget-access",
			Label: "bob: budget access denied but requestable (AARP approval gate)",
		},
	}
}
