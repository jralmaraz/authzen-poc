//go:build js && wasm

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"syscall/js"

	"github.com/jralmaraz/authzen-poc/pkg/authzen"
)

var pdp *authzen.InMemoryPDP

func main() {
	pdp = authzen.NewInMemoryPDP(authzen.DefaultRules())

	js.Global().Set("authzenInit", js.FuncOf(wasmInit))
	js.Global().Set("authzenEvaluate", js.FuncOf(wasmEvaluate))
	js.Global().Set("authzenEvaluateAll", js.FuncOf(wasmEvaluateAll))
	js.Global().Set("authzenAddRule", js.FuncOf(wasmAddRule))
	js.Global().Set("authzenRemoveRule", js.FuncOf(wasmRemoveRule))
	js.Global().Set("authzenListRules", js.FuncOf(wasmListRules))
	js.Global().Set("authzenToOpenFGA", js.FuncOf(wasmToOpenFGA))
	js.Global().Set("authzenToRego", js.FuncOf(wasmToRego))
	js.Global().Set("authzenSimulateAS", js.FuncOf(wasmSimulateAS))

	// Signal ready
	if cb := js.Global().Get("onAuthzenReady"); !cb.IsUndefined() {
		cb.Invoke()
	}

	select {} // keep alive
}

// wasmInit resets the PDP to default rules and returns them as JSON.
func wasmInit(_ js.Value, _ []js.Value) any {
	pdp = authzen.NewInMemoryPDP(authzen.DefaultRules())
	return mustJSON(pdp.Rules())
}

// wasmEvaluate evaluates a single AuthZEN EvaluationRequest JSON string.
// Returns: { decision: bool, matched_rule: string|null }
func wasmEvaluate(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errJSON("missing request argument")
	}
	var req authzen.EvaluationRequest
	if err := json.Unmarshal([]byte(args[0].String()), &req); err != nil {
		return errJSON("invalid request JSON: " + err.Error())
	}
	resp, matched := pdp.EvaluateWithReason(req)
	out := map[string]any{
		"decision":     resp.Decision,
		"matched_rule": nil,
	}
	if matched != nil {
		out["matched_rule"] = map[string]any{
			"index": matched.Index,
			"label": matched.Rule.Label,
			"decision": matched.Rule.Decision,
		}
	}
	return mustJSON(out)
}

// wasmEvaluateAll evaluates an EvaluationsRequest JSON (bulk).
func wasmEvaluateAll(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errJSON("missing request argument")
	}
	var req authzen.EvaluationsRequest
	if err := json.Unmarshal([]byte(args[0].String()), &req); err != nil {
		return errJSON("invalid request JSON: " + err.Error())
	}
	results := make([]map[string]any, 0, len(req.Evaluations))
	for _, e := range req.Evaluations {
		if e.Subject.ID == "" && e.Subject.Type == "" {
			e.Subject = req.Subject
		}
		resp, matched := pdp.EvaluateWithReason(e)
		item := map[string]any{
			"decision":     resp.Decision,
			"matched_rule": nil,
		}
		if matched != nil {
			item["matched_rule"] = map[string]any{
				"index": matched.Index,
				"label": matched.Rule.Label,
			}
		}
		results = append(results, item)
	}
	return mustJSON(map[string]any{"evaluations": results})
}

// wasmAddRule appends a PolicyRule from JSON and returns the updated rules list.
func wasmAddRule(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errJSON("missing rule argument")
	}
	var rule authzen.PolicyRule
	if err := json.Unmarshal([]byte(args[0].String()), &rule); err != nil {
		return errJSON("invalid rule JSON: " + err.Error())
	}
	pdp.AddRule(rule)
	return mustJSON(pdp.Rules())
}

// wasmRemoveRule removes the rule at the given index and returns updated rules.
func wasmRemoveRule(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errJSON("missing index argument")
	}
	idx := args[0].Int()
	if err := pdp.RemoveRule(idx); err != nil {
		return errJSON(err.Error())
	}
	return mustJSON(pdp.Rules())
}

// wasmListRules returns the current rules as JSON.
func wasmListRules(_ js.Value, _ []js.Value) any {
	return mustJSON(pdp.Rules())
}

// wasmToOpenFGA converts current rules to an OpenFGA model+tuples JSON.
func wasmToOpenFGA(_ js.Value, _ []js.Value) any {
	export := authzen.ToOpenFGA(pdp.Rules())
	return mustJSON(export)
}

// wasmToRego converts current rules to a Rego policy string.
func wasmToRego(_ js.Value, _ []js.Value) any {
	return authzen.ToRego(pdp.Rules())
}

// wasmSimulateAS simulates an OAuth AS calling AuthZEN during token exchange.
// Input JSON: { "subject_token": "<jwt>", "target_audience": "<url>", "subject_spiffe_id": "<override>" }
// The subject_token is base64-decoded to extract the sub claim (SPIFFE ID).
func wasmSimulateAS(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errJSON("missing input argument")
	}
	var input struct {
		SubjectToken    string `json:"subject_token"`
		TargetAudience  string `json:"target_audience"`
		SubjectSPIFFEID string `json:"subject_spiffe_id"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &input); err != nil {
		return errJSON("invalid input JSON: " + err.Error())
	}

	// Step 1 — AS receives token exchange request
	exchangeReq := map[string]any{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":        input.SubjectToken,
		"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
		"requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"audience":             input.TargetAudience,
	}

	// Step 2 — extract SPIFFE ID from subject_token (or use provided override)
	spiffeID := input.SubjectSPIFFEID
	if spiffeID == "" {
		spiffeID = extractSub(input.SubjectToken)
	}
	if spiffeID == "" {
		spiffeID = "spiffe://example.com/agents/orchestrator"
	}

	// Step 3 — AS constructs AuthZEN evaluation request
	evalReq := authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "workload", ID: spiffeID},
		Resource: authzen.Resource{Type: "token-audience", ID: input.TargetAudience},
		Action:   authzen.Action{Name: "exchange"},
	}

	// Step 4 — PDP evaluates
	resp, matched := pdp.EvaluateWithReason(evalReq)

	// Step 5 — AS issues or rejects token
	var matchedLabel string
	if matched != nil {
		matchedLabel = matched.Rule.Label
	}

	result := map[string]any{
		"steps": []map[string]any{
			{
				"step":  1,
				"label": "AS receives Token Exchange request (RFC 8693)",
				"data":  exchangeReq,
			},
			{
				"step":  2,
				"label": "AS extracts subject identity from subject_token",
				"data":  map[string]any{"sub": spiffeID, "method": "JWT payload decode"},
			},
			{
				"step":  3,
				"label": "AS constructs AuthZEN evaluation request",
				"data": map[string]any{
					"endpoint": "POST /access/v1/evaluation",
					"body":     evalReq,
				},
			},
			{
				"step":  4,
				"label": "PDP evaluates request",
				"data": map[string]any{
					"decision":     resp.Decision,
					"matched_rule": matchedLabel,
					"default_deny": matched == nil,
				},
			},
			{
				"step":  5,
				"label": func() string {
					if resp.Decision {
						return "AS issues token (decision: allow)"
					}
					return "AS rejects request — returns 403 Forbidden (decision: deny)"
				}(),
				"data": map[string]any{
					"token_issued": resp.Decision,
					"audience":     input.TargetAudience,
				},
			},
		},
		"decision":     resp.Decision,
		"subject_id":   spiffeID,
		"audience":     input.TargetAudience,
		"matched_rule": matchedLabel,
	}
	return mustJSON(result)
}

// extractSub base64-decodes the JWT payload and extracts the "sub" claim.
// Does NOT verify the signature — simulation only.
func extractSub(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func errJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

func init() {
	// Needed for js.Value.Int() to be available.
	_ = context.Background()
}
