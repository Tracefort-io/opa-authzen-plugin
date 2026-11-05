// Package store persists the state of the Access Request Service: tasks,
// their items, approver decisions, approvals, idempotency keys and seen
// binding_token identifiers. Every replica of the PDP shares one store, so
// all coordination between replicas happens here: unique keys for
// idempotency and replay, row locks for decisions, and SKIP LOCKED claims for
// the expiry sweeper.
package store

import (
	"context"
	"errors"
	"time"
)

// Task statuses (ARAP "Task Status and Transitions").
const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled"
	StatusFailed    = "failed"
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

// Task is one Access Request. Phase 1 tasks carry exactly one item.
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
	// CurrentStep is the zero-based index of the step in progress.
	CurrentStep int
	Display     map[string]any
	Items       []Item
	Decisions   []Decision
	ExpiresAt   time.Time
	CreatedAt   time.Time
	CompletedAt *time.Time
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
	// JTI is the binding_token identifier, recorded to detect replay.
	JTI        string
	JTIExpires time.Time
}

// Change is what an UpdateTask callback asks to persist.
type Change struct {
	Status       string // empty: unchanged
	CurrentStep  *int
	CompletedAt  *time.Time
	ItemStatus   map[int]string
	ItemApproval map[int]string
	NewDecisions []Decision
	NewApprovals []*Approval
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
	// ListPending returns pending tasks whose current step lists a `user`
	// approver with the given id, ordered by task id, after the cursor.
	ListPending(ctx context.Context, approverID, after string, limit int) (tasks []*Task, next string, err error)
	// GetApproval loads an approval.
	GetApproval(ctx context.Context, id string) (*Approval, error)
	// RevokeApproval marks an approval revoked; ErrConflict if it already is.
	RevokeApproval(ctx context.Context, id, by, reason string, now time.Time) (*Approval, error)
	// ExpireDue moves up to limit pending tasks whose expiry has passed to
	// expired and returns their ids. Safe to run on every replica at once.
	ExpireDue(ctx context.Context, now time.Time, limit int) ([]string, error)
	// Close releases the store's resources.
	Close()
}

// IsTerminal reports whether a status admits no further transition.
func IsTerminal(status string) bool {
	return status != StatusPending
}
