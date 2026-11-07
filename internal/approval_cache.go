package internal

import (
	"container/list"
	"sync"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// approvalCacheSize bounds the approvals one replica caches.
const approvalCacheSize = 10000

// approvalCache holds, per replica, approvals found in force at
// re-evaluation (approval_cache_ttl, design §19.3), so repeated
// re-evaluations skip the store. Only the record is cached: scope is still
// compared on every evaluation. Revoked or lapsed approvals are never
// cached, and an entry is dropped at its TTL or approved_until, whichever
// comes first. A revocation on this replica drops its entry at once; other
// replicas may honour a revoked approval for up to the TTL.
type approvalCache struct {
	ttl time.Duration
	max int

	mu      sync.Mutex
	order   *list.List // front: most recently used
	entries map[string]*list.Element
}

type cachedApproval struct {
	approval *store.Approval
	until    time.Time
}

func newApprovalCache(ttl time.Duration) *approvalCache {
	if ttl <= 0 {
		return nil
	}
	return &approvalCache{ttl: ttl, max: approvalCacheSize, order: list.New(), entries: map[string]*list.Element{}}
}

// get returns a cached approval still in force at now.
func (c *approvalCache) get(id string, now time.Time) *store.Approval {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[id]
	if !ok {
		return nil
	}
	e := el.Value.(*cachedApproval)
	if now.After(e.until) {
		c.order.Remove(el)
		delete(c.entries, id)
		return nil
	}
	c.order.MoveToFront(el)
	return e.approval
}

// put caches an approval in force at now.
func (c *approvalCache) put(a *store.Approval, now time.Time) {
	if c == nil || a.RevokedAt != nil || now.After(a.ApprovedUntil) {
		return
	}
	until := now.Add(c.ttl)
	if a.ApprovedUntil.Before(until) {
		until = a.ApprovedUntil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[a.ID]; ok {
		el.Value = &cachedApproval{approval: a, until: until}
		c.order.MoveToFront(el)
		return
	}
	c.entries[a.ID] = c.order.PushFront(&cachedApproval{approval: a, until: until})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.entries, last.Value.(*cachedApproval).approval.ID)
	}
}

// drop forgets an approval, as when it is revoked.
func (c *approvalCache) drop(id string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[id]; ok {
		c.order.Remove(el)
		delete(c.entries, id)
	}
}
