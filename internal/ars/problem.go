package ars

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
)

// Problem types defined by ARAP ("Error Responses").
const (
	problemPrefix         = "urn:openid:authzen:access-request:error:"
	ProblemNotRequestable = problemPrefix + "not_requestable"
	ProblemExpiredDenial  = problemPrefix + "expired_denial"
	ProblemInvalidBinding = problemPrefix + "invalid_denial_binding"
	ProblemDuplicate      = problemPrefix + "duplicate_request"
	ProblemUnknownTask    = problemPrefix + "unknown_task"
	ProblemTaskExpired    = problemPrefix + "task_expired"
	ProblemInvalidState   = problemPrefix + "invalid_task_state"
	problemGeneric        = "about:blank"
	problemContentType    = "application/problem+json"
)

// writeProblem writes an RFC 9457 problem document.
func writeProblem(w http.ResponseWriter, status int, typ, title, detail string) {
	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(status)
	body := map[string]any{"type": typ, "title": title, "status": status}
	if detail != "" {
		body["detail"] = detail
	}
	_ = json.NewEncoder(w).Encode(body)
}

func badRequest(w http.ResponseWriter, detail string) {
	writeProblem(w, http.StatusBadRequest, problemGeneric, "Bad request", detail)
}

// authenticate verifies the request's token with v, answering 401 with the
// verifier's challenges (Bearer, DPoP) when it fails, and 500 when proof
// verification could not consult its replay store.
func (s *Service) authenticate(w http.ResponseWriter, r *http.Request, v *authn.Verifier, api string) (*authn.Identity, bool) {
	id, err := v.Authenticate(r)
	switch {
	case err == nil:
		return id, true
	case !errors.Is(err, authn.ErrUnauthenticated):
		s.d.Logger.Error("AuthZEN access request service: authenticating: %v", err)
		s.d.Metrics.Count(r.Context(), MetricDBErrors, map[string]string{"operation": "replay"})
		internalError(w)
		return nil, false
	}
	s.d.Metrics.Count(r.Context(), MetricAuthFailures, map[string]string{"api": api, "reason": authn.Reason(err)})
	for _, c := range v.Challenges(s.d.BaseURL, err) {
		w.Header().Add("WWW-Authenticate", c)
	}
	writeProblem(w, http.StatusUnauthorized, problemGeneric, "Unauthenticated", "a valid access token is required")
	return nil, false
}

func forbidden(w http.ResponseWriter) {
	writeProblem(w, http.StatusForbidden, problemGeneric, "Forbidden", "")
}

func unknownTask(w http.ResponseWriter) {
	writeProblem(w, http.StatusNotFound, ProblemUnknownTask, "Unknown task", "")
}

func internalError(w http.ResponseWriter) {
	writeProblem(w, http.StatusInternalServerError, problemGeneric, "Internal error", "")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
