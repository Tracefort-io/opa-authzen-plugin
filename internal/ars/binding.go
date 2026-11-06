package ars

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"
)

// WithoutActor copies an AuthZEN Subject without `properties.act`, which
// ARAP excludes from every binding comparison because a PEP may move the
// actor to `client.actor` ("Structural Comparison"). A PEP that does so may
// also drop a `properties` object left empty, so `properties` emptied by
// removing the actor is removed too: both forms of the same subject compare
// equal.
func WithoutActor(v any) any {
	subject, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(subject))
	for k, val := range subject {
		out[k] = val
	}
	if props, ok := subject["properties"].(map[string]any); ok {
		if _, has := props["act"]; has {
			copied := make(map[string]any, len(props))
			for k, val := range props {
				if k != "act" {
					copied[k] = val
				}
			}
			if len(copied) == 0 {
				delete(out, "properties")
			} else {
				out["properties"] = copied
			}
		}
	}
	return out
}

// RelevantContext returns the authorization-relevant members of a request
// context: those named in members that are present. An absent member stays
// absent, which ARAP distinguishes from one set to null.
func RelevantContext(ctx map[string]any, members []string) map[string]any {
	out := map[string]any{}
	for _, m := range members {
		if v, ok := ctx[m]; ok {
			out[m] = v
		}
	}
	return out
}

// SameBinding reports whether two Subject/Resource/Action/Context bindings
// are equal under ARAP structural comparison. Values are normalized through
// JSON first, so numbers compare by value whatever Go type carried them.
func SameBinding(a, b any) bool {
	return reflect.DeepEqual(normalize(a), normalize(b))
}

func normalize(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return v
	}
	return out
}

// verifiedDenial is what a binding_token establishes about one item.
type verifiedDenial struct {
	claims  map[string]any
	echo    *denialEcho
	jti     string
	exp     time.Time
	members []string
}

// record is the item's denial as stored: the verified claims that scope its
// approval, and the echoed members shown to approvers.
func (v *verifiedDenial) record() map[string]any {
	evalID, _ := v.claims["evaluation_id"].(string)
	return map[string]any{
		"expires_at": v.echo.ExpiresAt, "evaluation_id": evalID, "evaluated_at": v.echo.EvaluatedAt,
		"reason": v.echo.Reason, "template": v.echo.Template,
		"binding_context_members": v.members, "context": v.claims["context"],
	}
}

var (
	errExpiredDenial  = errors.New("expired denial")
	errInvalidBinding = errors.New("invalid denial binding")
)

// verifyBinding applies ARAP "Verifying the Denial Binding" to one item of
// a submission, whose binding_token signature has already verified. Each
// item is bound by its own token: this PDP signs one per evaluation, so it
// never issues the Bulk Profile's bundle denial, and a token covering a
// different item fails here.
func (s *Service) verifyBinding(claims map[string]any, sub *submission, it *subItem) (*verifiedDenial, error) {
	echo := sub.denialFor(it)
	invalid := func(format string, args ...any) (*verifiedDenial, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{errInvalidBinding}, args...)...)
	}
	now := s.now()

	if iss, _ := claims["iss"].(string); iss != s.d.BaseURL {
		return invalid("iss is not this PDP")
	}
	if !audienceIncludes(claims["aud"], s.d.Audience) {
		return invalid("aud does not name this Access Request Service")
	}
	expF, ok := claims["exp"].(float64)
	if !ok {
		return invalid("exp is required")
	}
	exp := time.Unix(int64(expF), 0)
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return invalid("jti is required")
	}

	// The PEP-echoed expiry must match the protected one before it counts.
	echoed, err := time.Parse(time.RFC3339, echo.ExpiresAt)
	if err != nil {
		return invalid("denial.expires_at is not an RFC 3339 timestamp")
	}
	if protected, ok := claims["denial_expires_at"].(string); ok {
		if protected != echo.ExpiresAt {
			return invalid("denial.expires_at does not match the binding_token")
		}
	} else if exp.After(echoed) {
		return invalid("binding_token proves no freshness window no later than denial.expires_at")
	}
	deadline := exp
	if echoed.Before(deadline) {
		deadline = echoed
	}
	if now.After(deadline.Add(clockSkew)) {
		return nil, errExpiredDenial
	}

	if echo.EvaluationID != "" {
		if id, _ := claims["evaluation_id"].(string); id != echo.EvaluationID {
			return invalid("denial.evaluation_id does not match the binding_token")
		}
	}

	members := []string{}
	if v, ok := claims["binding_context_members"]; ok {
		list, ok := v.([]any)
		if !ok {
			return invalid("binding_context_members must be an array")
		}
		for _, m := range list {
			name, ok := m.(string)
			if !ok {
				return invalid("binding_context_members must hold strings")
			}
			members = append(members, name)
		}
	}
	boundCtx, _ := claims["context"].(map[string]any)
	if boundCtx == nil {
		boundCtx = map[string]any{}
	}
	switch {
	case !SameBinding(WithoutActor(claims["subject"]), WithoutActor(sub.Subject)):
		return invalid("subject does not match the denied evaluation")
	case !SameBinding(claims["resource"], it.Resource):
		return invalid("resource does not match the denied evaluation")
	case !SameBinding(claims["action"], it.Action):
		return invalid("action does not match the denied evaluation")
	case !SameBinding(boundCtx, RelevantContext(sub.Context, members)):
		return invalid("authorization-relevant context does not match the denied evaluation")
	}
	return &verifiedDenial{claims: claims, echo: echo, jti: jti, exp: exp, members: members}, nil
}

func audienceIncludes(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		return slices.ContainsFunc(a, func(v any) bool { s, _ := v.(string); return s == want })
	}
	return false
}
