package authzen

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Handler returns an http.Handler serving the AuthZEN Authorization API v1.
//
//	POST /access/v1/evaluation   — single access evaluation (§5.1)
//	POST /access/v1/evaluations  — bulk access evaluations (§5.2)
func Handler(pdp PDP) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /access/v1/evaluation", handleEvaluation(pdp))
	mux.HandleFunc("POST /access/v1/evaluations", handleEvaluations(pdp))
	return mux
}

func handleEvaluation(pdp PDP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := pdp.Evaluate(context.Background(), req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, resp)
	}
}

func handleEvaluations(pdp PDP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req EvaluationsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		results := make([]EvaluationResponse, 0, len(req.Evaluations))
		for _, e := range req.Evaluations {
			if e.Subject.ID == "" && e.Subject.Type == "" {
				e.Subject = req.Subject
			}
			resp, err := pdp.Evaluate(context.Background(), e)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			results = append(results, resp)
		}
		writeJSON(w, EvaluationsResponse{Evaluations: results})
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
