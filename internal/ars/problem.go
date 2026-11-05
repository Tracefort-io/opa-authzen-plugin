package ars

import (
	"encoding/json"
	"net/http"
)

// Problem types defined by ARAP ("Error Responses").
const (
	problemPrefix            = "urn:openid:authzen:access-request:error:"
	ProblemNotRequestable    = problemPrefix + "not_requestable"
	ProblemExpiredDenial     = problemPrefix + "expired_denial"
	ProblemInvalidBinding    = problemPrefix + "invalid_denial_binding"
	ProblemDuplicate         = problemPrefix + "duplicate_request"
	ProblemUnknownTask       = problemPrefix + "unknown_task"
	ProblemTaskExpired       = problemPrefix + "task_expired"
	ProblemInvalidState      = problemPrefix + "invalid_task_state"
	problemGeneric           = "about:blank"
	problemContentType       = "application/problem+json"
	unauthenticatedChallenge = `Bearer error="invalid_token"`
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

func unauthenticated(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", unauthenticatedChallenge)
	writeProblem(w, http.StatusUnauthorized, problemGeneric, "Unauthenticated", "a valid bearer token is required")
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
