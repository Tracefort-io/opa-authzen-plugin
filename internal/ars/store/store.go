// Package store persists the state of the Access Request Service: tasks,
// their items, approver decisions, approvals, idempotency keys, seen
// binding_token identifiers and pending callback notifications. Every replica
// of the PDP shares one store, so all coordination between replicas happens
// here: unique keys for idempotency and replay, row locks for decisions, and
// SKIP LOCKED claims for the expiry sweeper, callback delivery and purge.
package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Task statuses (ARAP "Task Status and Transitions"; `partial` from the Bulk
// Profile).
const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled"
	StatusFailed    = "failed"
	StatusPartial   = "partial"
)

// Decisions an approver can record.
const (
	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

var (
	// ErrNotFound is returned when a task or approval does not exist.
	ErrNotFound = errors.New("not found")
	// ErrDuplicateRequest is returned when an Idempotency-Key is reused by
	// the same requester with a materially different body.
	ErrDuplicateRequest = errors.New("idempotency key reused with a different request")
	// ErrReplay is returned when a binding_token jti has been seen before.
	ErrReplay = errors.New("binding_token has already been used")
	// ErrConflict is returned when a change cannot apply to the current
	// state: an approver deciding twice, or revoking a revoked approval.
	ErrConflict = errors.New("conflicting change")
)

// Task is one Access Request: one item, or several when the submission
// carried `items` (Bulk Profile).
type Task struct {
	ID              string
	Status          string
	Version         int
	RequesterIss    string
	RequesterSub    string
	RequesterClient string
	Subject         map[string]any
	Context         map[string]any
	RequestedAccess map[string]any
	Client          map[string]any
	// Denial holds the verified binding_token claims and the echoed denial
	// members; the token itself is not kept.
	Denial       map[string]any
	Template     string
	EvaluationID string
	Workflow     Workflow
	// CurrentStep is the zero-based index of the earliest step any pending
	// item is at; each item tracks its own step.
	CurrentStep int
	Display     map[string]any
	// Bulk records that the submission carried `items`, so the task handle
	// reports per-item status even for a single item.
	Bulk bool
	// Callback is the Callback Profile `callback` member, when submitted.
	Callback    *Callback
	Items       []Item
	Decisions   []Decision
	ExpiresAt   time.Time
	CreatedAt   time.Time
	CompletedAt *time.Time
}

// Callback is where and for which events to notify the PEP of completion.
type Callback struct {
	Endpoint string   `json:"endpoint"`
	State    string   `json:"state,omitempty"`
	Events   []string `json:"events,omitempty"`
}

// Wants reports whether the callback asked for a terminal status; no events
// means every terminal status.
func (c *Callback) Wants(status string) bool {
	return c != nil && IsTerminal(status) && (len(c.Events) == 0 || slices.Contains(c.Events, status))
}

// Workflow is the plan the workflow rule returned at submission.
type Workflow struct {
	Steps         []Step     `json:"steps"`
	ApprovedUntil *time.Time `json:"approved_until,omitempty"`
}

// Step is one approval step: Required approvals from Approvers.
type Step struct {
	Name              string           `json:"name"`
	Required          int              `json:"required"`
	Approvers         []map[string]any `json:"approvers"`
	DiscloseApprovers bool             `json:"disclose_approvers,omitempty"`
}

// Item is one requested Resource and Action.
type Item struct {
	Index           int
	Resource        map[string]any
	Action          map[string]any
	RequestedAccess map[string]any
	Status          string
	ApprovalID      string
	// CurrentStep is the zero-based workflow step this item is at.
	CurrentStep int
	// Denial is the item's verified denial: its evaluation, binding context
	// members, bound context and expiry. Nil for tasks stored before it was
	// kept per item; Task.Denial applies to those.
	Denial map[string]any
}

// Decision is one approver action on one item at one step.
type Decision struct {
	ItemIndex   int
	Step        int
	ApproverIss string
	ApproverSub string
	Decision    string
	Comment     string
	DecidedAt   time.Time
	// ApprovedUntil is the lifetime the approver shortened the approval to.
	ApprovedUntil *time.Time
}

// Approval is what an approved item grants: the bound request it applies to
// and its lifetime. Re-evaluation resolves `context.approval.id` to one.
type Approval struct {
	ID                    string
	TaskID                string
	ItemIndex             int
	Subject               map[string]any
	Resource              map[string]any
	Action                map[string]any
	BindingContextMembers []string
	Context               map[string]any
	ApprovedAt            time.Time
	ApprovedUntil         time.Time
	RevokedAt             *time.Time
	RevokedBy             string
	RevokeReason          string
}

// Idempotency identifies a submission for retry deduplication. A zero Key
// means the submission carried no Idempotency-Key.
type Idempotency struct {
	Requester   string
	Key         string
	BodyHash    []byte
	RetainUntil time.Time
}

// NewTask is everything CreateTask stores in one transaction.
type NewTask struct {
	Task        *Task
	Approvals   []*Approval
	Idempotency Idempotency
	// JTIs are the binding_token identifiers, recorded to detect replay.
	JTIs []JTI
}

// JTI is a binding_token identifier and when the token expires.
type JTI struct {
	ID      string
	Expires time.Time
}

// Change is what an UpdateTask callback asks to persist.
type Change struct {
	Status       string // empty: unchanged
	CurrentStep  *int
	CompletedAt  *time.Time
	ItemStatus   map[int]string
	ItemApproval map[int]string
	ItemStep     map[int]int
	NewDecisions []Decision
	NewApprovals []*Approval
}

// Delivery is a claimed callback notification: the task whose terminal
// status to report, and the attempts made so far, this one included.
type Delivery struct {
	ID       int64
	TaskID   string
	Event    string
	Attempts int
}

// PurgeCutoffs bound what Purge deletes.
type PurgeCutoffs struct {
	// Tasks: terminal tasks whose expires_at is before this, unless one of
	// their approvals is still in force.
	Tasks time.Time
	// Approvals: an approval is in force until its approved_until passes
	// this. Approvals are deleted with their task.
	Approvals time.Time
	// Now: idempotency keys past retain_until and binding_token
	// identifiers past their expiry.
	Now time.Time
}

// Store is the persistence contract of the Access Request Service.
type Store interface {
	// CreateTask stores a new task. When the idempotency key was already
	// used by the same requester with the same body hash, it returns that
	// task and existed=true and stores nothing; with a different hash it
	// returns ErrDuplicateRequest. A seen JTI returns ErrReplay.
	CreateTask(ctx context.Context, n *NewTask, now time.Time) (task *Task, existed bool, err error)
	// GetTask loads a task with its items and decisions.
	GetTask(ctx context.Context, id string) (*Task, error)
	// UpdateTask locks the task, passes it to fn, and persists the Change fn
	// returns. A nil Change persists nothing. An error from fn aborts.
	UpdateTask(ctx context.Context, id string, fn func(*Task) (*Change, error)) (*Task, error)
	// ListPending returns pending tasks with a pending item whose current
	// step lists a `user` approver with the given id, ordered by task id,
	// after the cursor.
	ListPending(ctx context.Context, approverID, after string, limit int) (tasks []*Task, next string, err error)
	// GetApproval loads an approval.
	GetApproval(ctx context.Context, id string) (*Approval, error)
	// RevokeApproval marks an approval revoked; ErrConflict if it already is.
	RevokeApproval(ctx context.Context, id, by, reason string, now time.Time) (*Approval, error)
	// ExpireDue expires the pending items of up to limit pending tasks whose
	// expiry has passed, recomputes their status, and returns their ids.
	// Safe to run on every replica at once.
	ExpireDue(ctx context.Context, now time.Time, limit int) ([]*Task, error)
	// ClaimCallbacks claims up to limit due callback notifications for
	// lease, counting an attempt for each. A claim whose lease lapses
	// becomes claimable again.
	ClaimCallbacks(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]Delivery, error)
	// MarkDelivered records a delivered notification.
	MarkDelivered(ctx context.Context, id int64, now time.Time) error
	// RetryCallback releases a failed attempt for another at next.
	RetryCallback(ctx context.Context, id int64, next time.Time, lastErr string) error
	// FailCallback gives a notification up.
	FailCallback(ctx context.Context, id int64, now time.Time, lastErr string) error
	// RememberJTI records a proof identifier, such as a DPoP proof's, until
	// expires; false means it was recorded before. Shared by all replicas.
	RememberJTI(ctx context.Context, id string, expires time.Time) (bool, error)
	// Backlog counts pending tasks and undelivered callback notifications.
	Backlog(ctx context.Context) (pendingTasks, undeliveredCallbacks int64, err error)
	// Purge deletes up to limit expired rows of each kind (PurgeCutoffs) and
	// returns the most rows it deleted of any one kind, so a caller repeats
	// while that reaches limit.
	Purge(ctx context.Context, c PurgeCutoffs, limit int) (int, error)
	// Close releases the store's resources.
	Close()
}

// IsTerminal reports whether a status admits no further transition.
func IsTerminal(status string) bool {
	return status != StatusPending
}

// Aggregate computes a task's status from its items (Bulk Profile
// "Response Items and Aggregation"): pending while any item is, the shared
// status when all items ended alike, partial otherwise.
func Aggregate(items []Item) string {
	status := ""
	for _, it := range items {
		switch {
		case it.Status == StatusPending:
			return StatusPending
		case status == "":
			status = it.Status
		case status != it.Status:
			status = StatusPartial
		}
	}
	if status == "" {
		return StatusPending
	}
	return status
}

// EarliestStep is the lowest step any pending item is at, or 0 when none is
// pending.
func EarliestStep(items []Item) int {
	step := -1
	for _, it := range items {
		if it.Status == StatusPending && (step < 0 || it.CurrentStep < step) {
			step = it.CurrentStep
		}
	}
	return max(step, 0)
}
