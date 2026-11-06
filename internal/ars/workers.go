package ars

import (
	"context"
	"errors"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

const (
	sweepInterval = 30 * time.Second
	sweepBatch    = 100
	purgeInterval = 10 * time.Minute
	purgeBatch    = 500
)

// RunSweeper expires pending tasks whose task.expires_at has passed (ARAP
// "State Transitions": pending to expired), until ctx is done. Every replica
// runs one; the store's claims keep them from expiring a task twice.
func (s *Service) RunSweeper(ctx context.Context) {
	runEvery(ctx, sweepInterval, s.sweep)
}

// RunPurger deletes what the service no longer needs (design §17.5), until
// ctx is done. Every replica runs one.
func (s *Service) RunPurger(ctx context.Context) {
	runEvery(ctx, purgeInterval, s.purge)
}

func runEvery(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		fn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweep expires due tasks in batches until none are left. A bulk task with
// items completed before expiry becomes partial.
func (s *Service) sweep(ctx context.Context) {
	for {
		tasks, err := s.d.Store.ExpireDue(ctx, s.now(), sweepBatch)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				s.d.Logger.Error("AuthZEN access request service: expiring tasks: %v", err)
			}
			return
		}
		for _, t := range tasks {
			s.d.Audit.Emit(ctx, t.Status, s.auditTask(t, nil))
		}
		if len(tasks) < sweepBatch {
			return
		}
	}
}

// purge deletes, in batches, terminal tasks past their retention whose
// approvals have all lapsed (with their items, decisions, approvals and
// callback rows), lapsed idempotency keys and expired binding_token
// identifiers. Every deleted record was audited when it was made, so the
// audit trail keeps the history.
func (s *Service) purge(ctx context.Context) {
	for {
		now := s.now()
		n, err := s.d.Store.Purge(ctx, store.PurgeCutoffs{
			Tasks: now.Add(-s.d.IdempotencyRetention),
			// A revoked approval's signed approval.state is honoured until
			// approved_until plus clock skew, so its row must outlive that.
			Approvals: now.Add(-clockSkew),
			Now:       now,
		}, purgeBatch)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				s.d.Logger.Error("AuthZEN access request service: purging: %v", err)
			}
			return
		}
		if n < purgeBatch {
			return
		}
	}
}
