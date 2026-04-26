package reaper

import (
	"context"
	"log/slog"
	"time"

	"operax/internal/logging"
	"operax/internal/spec"
	"operax/internal/store"
)

// WorkspaceDestroyer defines the interface for destroying workspaces.
// This allows the reaper to be decoupled from the full orchestrator.
type WorkspaceDestroyer interface {
	DestroyWorkspace(ctx context.Context, id, actor, message string) error
}

// TTLReaper periodically finds and destroys expired workspaces.
// It can be deployed as a separate component from the main orchestrator,
// enabling independent scaling and deployment.
type TTLReaper struct {
	store     store.StateStore
	destroyer WorkspaceDestroyer
	interval  time.Duration
	logger    *slog.Logger
}

// New creates a new TTL reaper.
// interval specifies how often to check for expired workspaces.
func New(store store.StateStore, destroyer WorkspaceDestroyer, interval time.Duration) *TTLReaper {
	return &TTLReaper{
		store:     store,
		destroyer: destroyer,
		interval:  interval,
		logger:    logging.GetLogger(),
	}
}

// Run starts the reaper loop, checking for expired workspaces at the configured interval.
// It runs until the context is cancelled.
func (r *TTLReaper) Run(ctx context.Context) error {
	r.logger.Info("TTL reaper starting", "interval", r.interval)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("TTL reaper stopping", "reason", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			if err := r.reapOnce(ctx); err != nil {
				r.logger.Error("reaper cycle failed", "err", err)
				return err
			}
		}
	}
}

// ReapOnce performs a single reap cycle synchronously.
// Useful for testing or manual invocation.
func (r *TTLReaper) ReapOnce(ctx context.Context) error {
	return r.reapOnce(ctx)
}

// reapOnce finds all expired workspaces and destroys them.
func (r *TTLReaper) reapOnce(ctx context.Context) error {
	recs, err := r.store.List(ctx)
	if err != nil {
		r.logger.Error("failed to list workspaces", "err", err)
		return err
	}

	now := time.Now().UTC()
	expiredCount := 0

	for _, rec := range recs {
		// Skip already destroyed workspaces
		if rec.Workspace.State == spec.StateDestroyed {
			continue
		}

		// Check if workspace has expired
		if now.After(rec.Workspace.ExpiresAt) {
			expiredCount++
			r.logger.Info("destroying expired workspace", "id", rec.Workspace.ID, "expired_at", rec.Workspace.ExpiresAt)

			if err := r.destroyer.DestroyWorkspace(ctx, rec.Workspace.ID, "ttl-reaper", "workspace ttl elapsed"); err != nil {
				r.logger.Error("failed to destroy workspace", "id", rec.Workspace.ID, "err", err)
				// Continue with other workspaces instead of failing completely
				continue
			}
		}
	}

	if expiredCount > 0 {
		r.logger.Info("reaper cycle completed", "destroyed", expiredCount)
	}
	return nil
}
