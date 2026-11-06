package ars

import (
	"errors"
	"fmt"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
)

// maxActorDepth bounds the delegation chains the service compares.
const maxActorDepth = 10

var errActorUnverified = errors.New("actor chain not verified")

// actorLink is one (iss, sub) pair of a delegation chain, the canonical
// actor identifier of the Actor Delegation Profile.
type actorLink struct{ iss, sub string }

// verifyActor applies the Actor Delegation Profile's "Actor Chain
// Verification" to a submission. A claimed chain, in `client.actor` or in
// `subject.properties.act`, must equal the RFC 8693 `act` chain of the
// caller's token, link for link and of the same length. It returns the
// verified `client.actor`, or nil when the submission claims none there.
func verifyActor(caller *authn.Identity, sub *submission) (map[string]any, error) {
	var token []actorLink
	if caller.Act != nil {
		var err error
		if token, err = actChain(caller.Act, 0); err != nil {
			return nil, fmt.Errorf("%w: the caller's token act claim: %w", errActorUnverified, err)
		}
	}
	if props, ok := sub.Subject["properties"].(map[string]any); ok {
		if raw, has := props["act"]; has {
			act, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: subject.properties.act must be an object", errActorUnverified)
			}
			claimed, err := actChain(act, 0)
			if err != nil {
				return nil, fmt.Errorf("%w: subject.properties.act: %w", errActorUnverified, err)
			}
			if !sameChain(claimed, token) {
				return nil, fmt.Errorf("%w: subject.properties.act does not match the caller's credential", errActorUnverified)
			}
		}
	}
	raw, has := sub.Client["actor"]
	if !has {
		return nil, nil
	}
	actor, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: client.actor must be an object", errActorUnverified)
	}
	claimed, err := clientActorChain(actor)
	if err != nil {
		return nil, fmt.Errorf("%w: client.actor: %w", errActorUnverified, err)
	}
	if !sameChain(claimed, token) {
		return nil, fmt.Errorf("%w: client.actor does not match the caller's credential", errActorUnverified)
	}
	return actor, nil
}

// clientActorChain reads `client.actor`: the immediate actor as `id` and
// `issuer`, then its nested `act` chain.
func clientActorChain(actor map[string]any) ([]actorLink, error) {
	id, _ := actor["id"].(string)
	issuer, _ := actor["issuer"].(string)
	switch {
	case id == "":
		return nil, errors.New("id is required")
	case issuer == "":
		// The canonical identifier is the (iss, sub) pair; without the
		// issuer the actor cannot be compared.
		return nil, errors.New("issuer is required to verify the actor")
	}
	chain := []actorLink{{iss: issuer, sub: id}}
	if raw, has := actor["act"]; has {
		act, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("act must be an object")
		}
		rest, err := actChain(act, 1)
		if err != nil {
			return nil, err
		}
		chain = append(chain, rest...)
	}
	return chain, nil
}

// actChain reads an RFC 8693 `act` claim and its nested `act` members.
func actChain(act map[string]any, depth int) ([]actorLink, error) {
	var chain []actorLink
	for act != nil {
		if depth >= maxActorDepth {
			return nil, fmt.Errorf("delegation chain deeper than %d", maxActorDepth)
		}
		iss, _ := act["iss"].(string)
		sub, _ := act["sub"].(string)
		if iss == "" || sub == "" {
			return nil, errors.New("every act needs a string iss and sub")
		}
		chain = append(chain, actorLink{iss: iss, sub: sub})
		next, has := act["act"]
		if !has {
			break
		}
		if act, _ = next.(map[string]any); act == nil {
			return nil, errors.New("act must be an object")
		}
		depth++
	}
	return chain, nil
}

func sameChain(a, b []actorLink) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
