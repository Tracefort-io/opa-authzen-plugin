package internal

import (
	"fmt"
	"slices"
)

// Obligation Types defined by the AuthZEN Obligations Profile 1.0 ("Normative
// Obligation Types"). Their type-specific members are checked here; any other
// advertised type, `custom` included, is checked only for the common shape.
const (
	obligationStepUp             = "step-up"
	obligationNotification       = "notification"
	obligationSessionTermination = "session_termination"
)

// validateObligations checks an `obligations` member a policy returned, in
// a Decision context or on a Search result, against the Obligations Profile
// ("The Obligation Object"). It applies only to a PDP that opted into the
// profile (advertised is non-empty), so a policy that never claimed the
// profile keeps full control of its context.
//
// A PEP that cannot comply with an obligation must treat a permit as a deny,
// so an obligation the PEP cannot even parse silently turns a permit into a
// denial far from the policy that issued it. Rejecting the malformed value
// here reports the authoring error where it was made, and fails closed.
func validateObligations(v any, advertised []string) error {
	if len(advertised) == 0 {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("obligations must be an array; got %T", v)
	}
	ids := make(map[string]bool, len(list))
	for i, item := range list {
		obl, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("obligations[%d] must be an object; got %T", i, item)
		}
		id, _ := obl["id"].(string)
		if id == "" {
			return fmt.Errorf("obligations[%d].id is required and must be a non-empty string", i)
		}
		// "Uniquely identifies this Obligation instance within the
		// enclosing response context."
		if ids[id] {
			return fmt.Errorf("obligations[%d].id %q is not unique", i, id)
		}
		ids[id] = true
		typ, _ := obl["type"].(string)
		if typ == "" {
			return fmt.Errorf("obligations[%d].type is required and must be a non-empty string", i)
		}
		// The metadata tells PEPs which types this PDP may issue; issuing
		// another breaks that promise.
		if !slices.Contains(advertised, typ) {
			return fmt.Errorf("obligations[%d].type %q is not in supported_obligations", i, typ)
		}
		props, ok := obl["properties"].(map[string]any)
		if !ok {
			return fmt.Errorf("obligations[%d].properties is required and must be an object", i)
		}
		if err := validateObligationProperties(typ, props); err != nil {
			return fmt.Errorf("obligations[%d] (%s): %w", i, typ, err)
		}
	}
	return nil
}

// validateObligationProperties checks the members the profile requires of
// each Normative Obligation Type.
func validateObligationProperties(typ string, props map[string]any) error {
	switch typ {
	case obligationStepUp:
		if s, _ := props["acr_value"].(string); s == "" {
			return fmt.Errorf("properties.acr_value is required and must be a non-empty string")
		}
		if v, ok := props["amr_values"]; ok {
			if _, ok := stringArray(v); !ok {
				return fmt.Errorf("properties.amr_values must be an array of strings")
			}
		}
	case obligationNotification:
		to, ok := stringArray(props["to"])
		if !ok || len(to) == 0 {
			return fmt.Errorf("properties.to is required and must be a non-empty array of strings")
		}
		seen := make(map[string]bool, len(to))
		for _, d := range to {
			if d == "" {
				return fmt.Errorf("properties.to must not contain an empty destination")
			}
			if seen[d] {
				return fmt.Errorf("properties.to destination %q is not unique", d)
			}
			seen[d] = true
		}
		if _, ok := props["body"].(string); !ok {
			return fmt.Errorf("properties.body is required and must be a string")
		}
		if v, ok := props["topic"]; ok {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("properties.topic must be a string")
			}
		}
	case obligationSessionTermination:
		if s, _ := props["subject"].(string); s == "" {
			return fmt.Errorf("properties.subject is required and must be a non-empty string")
		}
	}
	return nil
}

// validateSearchObligations checks the per-result obligations of a Search
// response ("Obligations and Search Requests"). It returns an error message
// in the form normaliseSearchResults uses.
func validateSearchObligations(entities []any, advertised []string) string {
	if len(advertised) == 0 {
		return ""
	}
	for i, e := range entities {
		entity, ok := e.(searchEntity)
		if !ok {
			continue
		}
		v, present := entity["obligations"]
		if !present {
			continue
		}
		if err := validateObligations(v, advertised); err != nil {
			return fmt.Sprintf("results[%d]: %v", i, err)
		}
	}
	return ""
}
