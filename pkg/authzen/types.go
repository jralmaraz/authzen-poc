package authzen

// EvaluationRequest is an AuthZEN access evaluation request.
// Spec: OpenID AuthZEN Authorization API §5.
type EvaluationRequest struct {
	Subject  Subject  `json:"subject"`
	Resource Resource `json:"resource"`
	Action   Action   `json:"action"`
	Context  *Context `json:"context,omitempty"`
}

// Subject identifies the party requesting access.
type Subject struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Resource identifies the thing being accessed.
type Resource struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Action describes the operation the subject wants to perform.
type Action struct {
	Name       string            `json:"name"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Context carries additional environmental information.
type Context struct {
	Properties map[string]any `json:"properties,omitempty"`
}

// Obligation is a mandatory action the PEP MUST carry out when the decision is honoured.
// AuthZEN Obligations Profile 1.0 §3.
type Obligation struct {
	// ID is a URI identifying the obligation type (e.g. "urn:authzen:obligation:audit-log").
	ID string `json:"id"`
	// Parameters carries obligation-specific key/value data.
	Parameters map[string]string `json:"parameters,omitempty"`
}

// EvaluationResponse is the AuthZEN access evaluation response.
// AARP extends the binary Decision with an optional Pending outcome
// ("deny but requestable").
type EvaluationResponse struct {
	// Decision is true when access is allowed, false when denied.
	// When Pending is true, Decision is false and the subject may request access.
	Decision bool `json:"decision"`

	// Pending is true when access is denied but can be requested for approval.
	// AuthZEN AARP 1.0 §4 — third outcome: "deny but requestable".
	Pending bool `json:"pending,omitempty"`

	// ApprovalEndpoint is the URL where the subject can submit an approval request.
	// Only set when Pending is true. AARP 1.0 §4.2.
	ApprovalEndpoint string `json:"approval_endpoint,omitempty"`

	// Obligations is the list of mandatory actions the PEP must carry out.
	// AuthZEN Obligations Profile 1.0 §3. Only present on ALLOW decisions.
	Obligations []Obligation `json:"obligations,omitempty"`

	Context *Context `json:"context,omitempty"`
}

// EvaluationsRequest is an AuthZEN bulk evaluations request.
// The top-level Subject is shared across all evaluations unless overridden per-item.
type EvaluationsRequest struct {
	Subject     Subject             `json:"subject"`
	Evaluations []EvaluationRequest `json:"evaluations"`
}

// EvaluationsResponse is the AuthZEN bulk evaluations response.
type EvaluationsResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}
