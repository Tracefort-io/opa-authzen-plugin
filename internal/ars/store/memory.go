package store

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"sync"
	"time"
)

// Memory is an in-process Store for tests. It implements the same contract
// as Postgres under a single mutex; it is not shared between processes.
type Memory struct {
	mu          sync.Mutex
	tasks       map[string]*Task
	approvals   map[string]*Approval
	idempotency map[string]Idempotency // requester + "\x00" + key
	idemTask    map[string]string      // same key -> task id
	jtis        map[string]time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tasks:       map[string]*Task{},
		approvals:   map[string]*Approval{},
		idempotency: map[string]Idempotency{},
		idemTask:    map[string]string{},
		jtis:        map[string]time.Time{},
	}
}

func cloneTask(t *Task) *Task {
	c := *t
	c.Items = slices.Clone(t.Items)
	c.Decisions = slices.Clone(t.Decisions)
	c.Workflow.Steps = slices.Clone(t.Workflow.Steps)
	return &c
}

func cloneApproval(a *Approval) *Approval {
	c := *a
	c.BindingContextMembers = slices.Clone(a.BindingContextMembers)
	return &c
}

// CreateTask implements Store.
func (m *Memory) CreateTask(_ context.Context, n *NewTask, now time.Time) (*Task, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idemKey := n.Idempotency.Requester + "\x00" + n.Idempotency.Key
	if n.Idempotency.Key != "" {
		if prev, ok := m.idempotency[idemKey]; ok && prev.RetainUntil.After(now) {
			if !bytes.Equal(prev.BodyHash, n.Idempotency.BodyHash) {
				return nil, false, ErrDuplicateRequest
			}
			if t, ok := m.tasks[m.idemTask[idemKey]]; ok {
				return cloneTask(t), true, nil
			}
		}
	}
	if n.JTI != "" {
		if _, seen := m.jtis[n.JTI]; seen {
			return nil, false, ErrReplay
		}
		m.jtis[n.JTI] = n.JTIExpires
	}
	t := cloneTask(n.Task)
	m.tasks[t.ID] = t
	for _, a := range n.Approvals {
		m.approvals[a.ID] = cloneApproval(a)
	}
	if n.Idempotency.Key != "" {
		m.idempotency[idemKey] = n.Idempotency
		m.idemTask[idemKey] = t.ID
	}
	return cloneTask(t), false, nil
}

// GetTask implements Store.
func (m *Memory) GetTask(_ context.Context, id string) (*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneTask(t), nil
}

// UpdateTask implements Store.
func (m *Memory) UpdateTask(_ context.Context, id string, fn func(*Task) (*Change, error)) (*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.tasks[id]
	if !ok {
		return nil, ErrNotFound
	}
	t := cloneTask(stored)
	ch, err := fn(cloneTask(t))
	if err != nil {
		return nil, err
	}
	if ch == nil {
		return t, nil
	}
	for _, d := range ch.NewDecisions {
		for _, prev := range t.Decisions {
			if prev.ItemIndex == d.ItemIndex && prev.Step == d.Step && prev.ApproverIss == d.ApproverIss && prev.ApproverSub == d.ApproverSub {
				return nil, ErrConflict
			}
		}
	}
	applyChange(t, ch)
	m.tasks[id] = t
	for _, a := range ch.NewApprovals {
		m.approvals[a.ID] = cloneApproval(a)
	}
	return cloneTask(t), nil
}

// applyChange applies ch to t in memory. Shared with the Postgres store,
// which applies the same change to its returned copy.
func applyChange(t *Task, ch *Change) {
	if ch.Status != "" {
		t.Status = ch.Status
	}
	if ch.CurrentStep != nil {
		t.CurrentStep = *ch.CurrentStep
	}
	if ch.CompletedAt != nil {
		c := *ch.CompletedAt
		t.CompletedAt = &c
	}
	for i := range t.Items {
		if s, ok := ch.ItemStatus[t.Items[i].Index]; ok {
			t.Items[i].Status = s
		}
		if a, ok := ch.ItemApproval[t.Items[i].Index]; ok {
			t.Items[i].ApprovalID = a
		}
	}
	t.Decisions = append(t.Decisions, ch.NewDecisions...)
	t.Version++
}

// ListPending implements Store.
func (m *Memory) ListPending(_ context.Context, approverID, after string, limit int) ([]*Task, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, t := range m.tasks {
		if t.Status == StatusPending && id > after && currentStepLists(t, approverID) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	next := ""
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
		next = ids[len(ids)-1]
	}
	out := make([]*Task, len(ids))
	for i, id := range ids {
		out[i] = cloneTask(m.tasks[id])
	}
	return out, next, nil
}

func currentStepLists(t *Task, approverID string) bool {
	if t.CurrentStep >= len(t.Workflow.Steps) {
		return false
	}
	for _, a := range t.Workflow.Steps[t.CurrentStep].Approvers {
		if a["type"] == "user" && a["id"] == approverID {
			return true
		}
	}
	return false
}

// GetApproval implements Store.
func (m *Memory) GetApproval(_ context.Context, id string) (*Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approvals[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneApproval(a), nil
}

// RevokeApproval implements Store.
func (m *Memory) RevokeApproval(_ context.Context, id, by, reason string, now time.Time) (*Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approvals[id]
	if !ok {
		return nil, ErrNotFound
	}
	if a.RevokedAt != nil {
		return nil, ErrConflict
	}
	at := now
	a.RevokedAt, a.RevokedBy, a.RevokeReason = &at, by, reason
	return cloneApproval(a), nil
}

// ExpireDue implements Store.
func (m *Memory) ExpireDue(_ context.Context, now time.Time, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, t := range m.tasks {
		if t.Status == StatusPending && !t.ExpiresAt.After(now) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	for _, id := range ids {
		t := m.tasks[id]
		status := map[int]string{}
		for _, it := range t.Items {
			if it.Status == StatusPending {
				status[it.Index] = StatusExpired
			}
		}
		at := now
		applyChange(t, &Change{Status: StatusExpired, CompletedAt: &at, ItemStatus: status})
	}
	return ids, nil
}

// Close implements Store.
func (m *Memory) Close() {}
