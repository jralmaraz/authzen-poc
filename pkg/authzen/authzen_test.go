package authzen_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jralmaraz/authzen-poc/pkg/authzen"
)

func req(sType, sID, rType, rID, action string) authzen.EvaluationRequest {
	return authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: sType, ID: sID},
		Resource: authzen.Resource{Type: rType, ID: rID},
		Action:   authzen.Action{Name: action},
	}
}

func TestInMemoryPDP_Allow(t *testing.T) {
	pdp := authzen.NewInMemoryPDP([]authzen.PolicyRule{
		{SubjectType: "user", SubjectID: "alice@example.com", ResourceType: "document", ResourceID: "report", ActionName: "can_read", Decision: true, Priority: 10},
	})
	resp, err := pdp.Evaluate(context.Background(), req("user", "alice@example.com", "document", "report", "can_read"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !resp.Decision {
		t.Error("expected decision=true")
	}
}

func TestInMemoryPDP_DefaultDeny(t *testing.T) {
	pdp := authzen.NewInMemoryPDP(nil)
	resp, err := pdp.Evaluate(context.Background(), req("user", "alice@example.com", "document", "report", "can_read"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if resp.Decision {
		t.Error("expected default deny (no rules)")
	}
}

func TestInMemoryPDP_GlobSubjectID(t *testing.T) {
	pdp := authzen.NewInMemoryPDP([]authzen.PolicyRule{
		{SubjectType: "workload", SubjectID: "spiffe://*/agents/*", ResourceType: "tool", ResourceID: "search-api", ActionName: "invoke", Decision: true, Priority: 5},
	})
	// Should match any agent SPIFFE ID
	resp, _ := pdp.Evaluate(context.Background(), req("workload", "spiffe://mesh.example/agents/orchestrator", "tool", "search-api", "invoke"))
	if !resp.Decision {
		t.Error("expected match on glob subject")
	}
	// Should not match non-agent path
	resp2, _ := pdp.Evaluate(context.Background(), req("workload", "spiffe://mesh.example/services/db", "tool", "search-api", "invoke"))
	if resp2.Decision {
		t.Error("expected no match for non-agent path")
	}
}

func TestInMemoryPDP_GlobResourceID(t *testing.T) {
	pdp := authzen.NewInMemoryPDP([]authzen.PolicyRule{
		{SubjectType: "user", SubjectID: "alice@example.com", ResourceType: "document", ResourceID: "budget-*", ActionName: "can_edit", Decision: true, Priority: 10},
	})
	resp, _ := pdp.Evaluate(context.Background(), req("user", "alice@example.com", "document", "budget-2024", "can_edit"))
	if !resp.Decision {
		t.Error("expected match on budget-* glob")
	}
	resp2, _ := pdp.Evaluate(context.Background(), req("user", "alice@example.com", "document", "report-2024", "can_edit"))
	if resp2.Decision {
		t.Error("expected no match for non-budget resource")
	}
}

func TestInMemoryPDP_GlobActionName(t *testing.T) {
	pdp := authzen.NewInMemoryPDP([]authzen.PolicyRule{
		{SubjectType: "workload", SubjectID: "spiffe://*/admin/*", ResourceType: "*", ResourceID: "*", ActionName: "*", Decision: true, Priority: 20},
	})
	resp, _ := pdp.Evaluate(context.Background(), req("workload", "spiffe://corp.example/admin/billing", "secret", "vault-key", "read"))
	if !resp.Decision {
		t.Error("expected wildcard action match for admin workload")
	}
}

func TestInMemoryPDP_PriorityWins(t *testing.T) {
	pdp := authzen.NewInMemoryPDP([]authzen.PolicyRule{
		{SubjectType: "user", SubjectID: "*", ResourceType: "document", ResourceID: "*", ActionName: "*", Decision: false, Priority: 1, Label: "low-priority deny"},
		{SubjectType: "user", SubjectID: "alice@example.com", ResourceType: "document", ResourceID: "report", ActionName: "can_read", Decision: true, Priority: 10, Label: "high-priority allow"},
	})
	resp, _ := pdp.Evaluate(context.Background(), req("user", "alice@example.com", "document", "report", "can_read"))
	if !resp.Decision {
		t.Error("expected high-priority allow to win")
	}
}

func TestInMemoryPDP_ExplicitDenyWins(t *testing.T) {
	pdp := authzen.NewInMemoryPDP([]authzen.PolicyRule{
		{SubjectType: "user", SubjectID: "bob@example.com", ResourceType: "document", ResourceID: "*", ActionName: "*", Decision: false, Priority: 20, Label: "explicit deny for bob"},
		{SubjectType: "user", SubjectID: "bob@example.com", ResourceType: "document", ResourceID: "report", ActionName: "can_read", Decision: true, Priority: 10, Label: "lower-priority allow"},
	})
	resp, _ := pdp.Evaluate(context.Background(), req("user", "bob@example.com", "document", "report", "can_read"))
	if resp.Decision {
		t.Error("expected explicit deny to win over lower-priority allow")
	}
}

func TestInMemoryPDP_EvaluateWithReason(t *testing.T) {
	rule := authzen.PolicyRule{SubjectType: "user", SubjectID: "alice@example.com", ResourceType: "document", ResourceID: "*", ActionName: "can_read", Decision: true, Priority: 10, Label: "alice reads"}
	pdp := authzen.NewInMemoryPDP([]authzen.PolicyRule{rule})
	_, matched := pdp.EvaluateWithReason(req("user", "alice@example.com", "document", "any", "can_read"))
	if matched == nil {
		t.Fatal("expected a matched rule")
	}
	if matched.Rule.Label != "alice reads" {
		t.Errorf("wrong matched rule: %q", matched.Rule.Label)
	}
	// No match → nil
	_, matched2 := pdp.EvaluateWithReason(req("user", "eve@example.com", "document", "any", "can_read"))
	if matched2 != nil {
		t.Error("expected nil matched rule for default deny")
	}
}

func TestHTTPHandler_Evaluation(t *testing.T) {
	pdp := authzen.NewInMemoryPDP(authzen.DefaultRules())
	h := authzen.Handler(pdp)

	body, _ := json.Marshal(req("workload", "spiffe://mesh.example/agents/orchestrator", "token-audience", "https://api.cloud-b.example", "exchange"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d", w.Code)
	}
	var resp authzen.EvaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Decision {
		t.Error("expected orchestrator token exchange to be allowed")
	}
}

func TestHTTPHandler_Evaluations_Bulk(t *testing.T) {
	pdp := authzen.NewInMemoryPDP(authzen.DefaultRules())
	h := authzen.Handler(pdp)

	bulk := authzen.EvaluationsRequest{
		Subject: authzen.Subject{Type: "user", ID: "alice@example.com"},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: authzen.Resource{Type: "document", ID: "annual-report"}, Action: authzen.Action{Name: "can_read"}},
			{Resource: authzen.Resource{Type: "document", ID: "budget-2024"}, Action: authzen.Action{Name: "can_edit"}},
		},
	}
	body, _ := json.Marshal(bulk)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d", w.Code)
	}
	var resp authzen.EvaluationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Evaluations) != 2 {
		t.Fatalf("want 2 results, got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Error("alice should be able to can_read any document")
	}
	if !resp.Evaluations[1].Decision {
		t.Error("alice should be able to can_edit budget-* documents")
	}
}

func TestHTTPHandler_BadRequest(t *testing.T) {
	pdp := authzen.NewInMemoryPDP(nil)
	h := authzen.Handler(pdp)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", strings.NewReader("{bad json"))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestToOpenFGA_NonWildcardRules(t *testing.T) {
	rules := []authzen.PolicyRule{
		{SubjectType: "user", SubjectID: "alice@example.com", ResourceType: "document", ResourceID: "report", ActionName: "can_read", Decision: true, Priority: 10},
	}
	export := authzen.ToOpenFGA(rules)
	if !strings.Contains(export.Model, "type user") {
		t.Error("expected 'type user' in OpenFGA model")
	}
	if !strings.Contains(export.Model, "define can_read") {
		t.Error("expected 'define can_read' in OpenFGA model")
	}
	if !strings.Contains(export.Tuples, "alice@example.com") {
		t.Error("expected alice tuple in OpenFGA tuples")
	}
}

func TestToRego_GeneratesValidPolicy(t *testing.T) {
	rules := authzen.DefaultRules()
	policy := authzen.ToRego(rules)
	if !strings.Contains(policy, "package authzen") {
		t.Error("expected package declaration")
	}
	if !strings.Contains(policy, "default decision := false") {
		t.Error("expected default deny")
	}
	if !strings.Contains(policy, "decision := true") {
		t.Error("expected at least one allow rule")
	}
}
