package ars

import (
	"context"
	"errors"
	"time"
)

const (
	sweepInterval = 30 * time.Second
	sweepBatch    = 100
)

// RunSweeper expires pending tasks whose task.expires_at has passed (ARAP
// "State Transitions": pending to expired), until ctx is done. Every replica
// runs one; the store's claims keep them from expiring a task twice.
func (s *Service) RunSweeper(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		s.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweep expires due tasks in batches until none are left.
func (s *Service) sweep(ctx context.Context) {
	for {
		ids, err := s.d.Store.ExpireDue(ctx, s.now(), sweepBatch)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				s.d.Logger.Error("AuthZEN access request service: expiring tasks: %v", err)
			}
			return
		}
		for _, id := range ids {
			s.d.Audit.Emit(ctx, "expired", map[string]any{"task_id": id, "status": "expired", "actor": "system"})
		}
		if len(ids) < sweepBatch {
			return
		}
	}
}
