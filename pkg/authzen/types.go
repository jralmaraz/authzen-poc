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

// EvaluationResponse is the AuthZEN access evaluation response.
type EvaluationResponse struct {
	Decision bool     `json:"decision"`
	Context  *Context `json:"context,omitempty"`
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
