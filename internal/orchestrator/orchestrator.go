package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"operax/internal/audit"
	"operax/internal/concurrency"
	"operax/internal/journal"
	"operax/internal/logging"
	"operax/internal/pagination"
	"operax/internal/policy"
	"operax/internal/provision"
	"operax/internal/reaper"
	"operax/internal/spec"
	"operax/internal/store"
	"operax/internal/transaction"
)

type Orchestrator struct {
	provisioner provision.Provisioner
	resources   provision.ResourceManager
	store       store.StateStore
	audit       audit.Sink
	journal     *journal.Log
	wsLocks     *concurrency.WorkspaceCoordinator
	reaperEvery time.Duration
}

func New(
	provisioner provision.Provisioner,
	resources provision.ResourceManager,
	stateStore store.StateStore,
	sink audit.Sink,
	reaperEvery time.Duration,
) *Orchestrator {
	orch := &Orchestrator{
		provisioner: provisioner,
		resources:   resources,
		store:       stateStore,
		audit:       sink,
		reaperEvery: reaperEvery,
	}
	if fs, ok := stateStore.(*store.FileStore); ok {
		if j, err := journal.New(filepath.Join(fs.RootDir(), "journal")); err == nil {
			orch.journal = j
		}
		if lockMgr, err := concurrency.NewCoordinator(filepath.Join(fs.RootDir(), "locks")); err == nil {
			orch.wsLocks = lockMgr
		}
	}
	return orch
}

func (o *Orchestrator) Recover(ctx context.Context) error {
	if o.journal == nil {
		return nil
	}
	entries, err := o.journal.Pending()
	if err != nil {
		return err
	}
	for _, pending := range entries {
		if _, err := os.Stat(pending.StatePath); err == nil {
			if _, err := os.Stat(pending.AuditPath); err == nil {
				_ = o.journal.Commit(o.journal.PendingPath(pending.WorkspaceID))
				continue
			}
			rec, loadErr := o.store.Load(ctx, pending.WorkspaceID)
			if loadErr != nil {
				continue
			}
			if writeErr := o.audit.WriteRecord(ctx, rec.Audit); writeErr == nil {
				_ = o.journal.Commit(o.journal.PendingPath(pending.WorkspaceID))
			}
		}
	}
	return nil
}

// NewTTLReaper creates a new TTL reaper component for this orchestrator.
// The reaper can be deployed independently and will call DestroyWorkspace
// when workspaces have exceeded their TTL.
func (o *Orchestrator) NewTTLReaper() *reaper.TTLReaper {
	return reaper.New(o.store, o, o.reaperEvery)
}

func (o *Orchestrator) CreateWorkspace(ctx context.Context, wsSpec spec.WorkspaceSpec) (*spec.StateRecord, error) {
	unlock, err := o.lockWorkspace(wsSpec.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	logger := logging.FromContext(ctx)

	if wsSpec.CPUPeriod == 0 {
		wsSpec.CPUPeriod = 1_000_000
	}
	if err := wsSpec.Validate(); err != nil {
		logger.Error("workspace spec validation failed", "id", wsSpec.ID, "err", err)
		return nil, err
	}
	if err := policy.ValidateWorkspaceSpec(wsSpec); err != nil {
		logger.Error("workspace policy validation failed", "id", wsSpec.ID, "err", err)
		return nil, err
	}

	// Start transaction with rollback capability
	txn := transaction.New("CreateWorkspace(" + wsSpec.ID + ")")

	// Step 1: Create workspace directories and structure
	now := time.Now().UTC()
	ws, err := o.provisioner.Create(ctx, wsSpec)
	if err != nil {
		logger.Error("workspace provisioning failed", "id", wsSpec.ID, "err", err)
		return nil, err
	}
	ws.State = spec.StateReady

	// Register cleanup: destroy provisioned workspace if later steps fail
	txn.OnRollback(func() error {
		logger.Info("rolling back workspace provisioning", "id", wsSpec.ID)
		return o.provisioner.Destroy(ctx, ws)
	})

	// Step 2: Apply resource limits
	if err := o.resources.Apply(ws.ID, spec.ResourceLimits{
		CPUQuota:      wsSpec.CPUQuota,
		CPUPeriod:     wsSpec.CPUPeriod,
		MemLimitBytes: wsSpec.MemLimitBytes,
		IOReadBps:     wsSpec.IOReadBps,
		IOWriteBps:    wsSpec.IOWriteBps,
		PidsMax:       wsSpec.PidsMax,
	}); err != nil {
		logger.Error("resource limits apply failed", "id", wsSpec.ID, "err", err)
		if rollbackErr := txn.Rollback(); rollbackErr != nil {
			logger.Error("transaction rollback failed", "id", wsSpec.ID, "err", rollbackErr)
			return nil, fmt.Errorf("apply failed (%w) and rollback failed (%v)", err, rollbackErr)
		}
		return nil, err
	}

	// Register cleanup: remove resource limits if later steps fail
	txn.OnRollback(func() error {
		logger.Info("rolling back resource limits", "id", wsSpec.ID)
		return o.resources.Remove(ws.ID)
	})

	// Step 3: Bind init process to resource limits
	if ws.InitPID > 0 {
		if err := o.resources.BindProcess(ws.ID, ws.InitPID); err != nil {
			logger.Error("process binding failed", "id", wsSpec.ID, "pid", ws.InitPID, "err", err)
			if rollbackErr := txn.Rollback(); rollbackErr != nil {
				logger.Error("transaction rollback failed", "id", wsSpec.ID, "err", rollbackErr)
				return nil, fmt.Errorf("bind failed (%w) and rollback failed (%v)", err, rollbackErr)
			}
			return nil, err
		}
	}

	// Step 4: Retrieve initial resource metrics
	metrics, err := o.resources.Metrics(ws.ID)
	if err != nil {
		logger.Error("metrics retrieval failed", "id", wsSpec.ID, "err", err)
		if rollbackErr := txn.Rollback(); rollbackErr != nil {
			logger.Error("transaction rollback failed", "id", wsSpec.ID, "err", rollbackErr)
			return nil, fmt.Errorf("metrics failed (%w) and rollback failed (%v)", err, rollbackErr)
		}
		return nil, err
	}

	// Step 5: Create audit record
	auditRecord := spec.AuditRecord{
		WorkspaceID:         ws.ID,
		TenantID:            ws.TenantID,
		TranscriptPath:      ws.TranscriptPath,
		ResourceReport:      *metrics,
		EgressPolicy:        wsSpec.NetworkPolicy,
		SeccompProfileID:    wsSpec.SeccompProfileID,
		LastTransitionState: ws.State,
		UpdatedAt:           now,
		LifecycleEvents: []spec.LifecycleEvent{
			{
				WorkspaceID: ws.ID,
				From:        spec.StatePending,
				To:          spec.StateProvisioning,
				Actor:       "operax",
				Message:     "workspace request accepted",
				At:          now,
			},
			{
				WorkspaceID: ws.ID,
				From:        spec.StateProvisioning,
				To:          spec.StateReady,
				Actor:       "operax",
				Message:     "workspace prepared with overlay-style directories and policy metadata",
				At:          now,
			},
		},
	}

	rec := spec.StateRecord{
		Spec:      wsSpec,
		Workspace: *ws,
		Metrics:   *metrics,
		Audit:     auditRecord,
	}

	// Step 6: Persist state + audit with crash-recoverable journal
	if err := o.persistRecord(ctx, rec); err != nil {
		logger.Error("state store save failed", "id", wsSpec.ID, "err", err)
		if rollbackErr := txn.Rollback(); rollbackErr != nil {
			logger.Error("transaction rollback failed", "id", wsSpec.ID, "err", rollbackErr)
			return nil, fmt.Errorf("store save failed (%w) and rollback failed (%v)", err, rollbackErr)
		}
		return nil, err
	}

	// Register cleanup: delete state record if audit write fails (minimal risk but complete)
	txn.OnRollback(func() error {
		logger.Info("rolling back state store record", "id", wsSpec.ID)
		return o.store.Delete(ctx, wsSpec.ID)
	})

	// All steps succeeded - commit transaction and clear rollback actions
	txn.Commit()
	logger.Info("workspace created successfully with transaction safety", "id", wsSpec.ID)
	return &rec, nil
}

func (o *Orchestrator) AttachWorkspace(ctx context.Context, id string) error {
	unlock, err := o.lockWorkspace(id)
	if err != nil {
		return err
	}
	defer unlock()

	rec, err := o.store.Load(ctx, id)
	if err != nil {
		return err
	}
	if rec.Workspace.State == spec.StateDestroyed {
		return errors.New("workspace already destroyed")
	}
	if time.Now().UTC().After(rec.Workspace.ExpiresAt) {
		_ = o.DestroyWorkspace(ctx, id, "operax", "workspace ttl elapsed before attach")
		return errors.New("workspace expired; create a new workspace")
	}
	if _, err := os.Stat(rec.Workspace.RootDir); err != nil {
		if os.IsNotExist(err) {
			_ = o.transition(ctx, &rec, spec.StateDestroyed, "operax", "workspace root missing; treating workspace as destroyed")
			return errors.New("workspace filesystem is missing; create a new workspace")
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rec.Workspace.TranscriptPath), 0o755); err != nil {
		return err
	}

	if err := o.transition(ctx, &rec, spec.StateAttached, "operax", "workspace attached"); err != nil {
		return err
	}
	before, _ := dirSize(rec.Workspace.MergedDir)
	runErr := o.provisioner.Attach(ctx, rec.Spec, &rec.Workspace)
	after, _ := dirSize(rec.Workspace.MergedDir)
	transcriptSize, _ := fileSize(rec.Workspace.TranscriptPath)
	_ = o.resources.Observe(rec.Workspace.ID, spec.ResourceObservation{
		MemoryCurrent:     minPositive(rec.Spec.MemLimitBytes, after),
		IOWriteBytesDelta: transcriptSize,
		PidsCurrent:       1,
	})
	if runErr != nil {
		appendViolations(&rec, policy.EvaluateCommand(rec.Spec, 0))
		if err := o.transition(ctx, &rec, spec.StateFailed, "operax", runErr.Error()); err != nil {
			return err
		}
		return runErr
	}
	_ = o.resources.Observe(rec.Workspace.ID, spec.ResourceObservation{
		MemoryCurrent:    minPositive(rec.Spec.MemLimitBytes, after),
		IOReadBytesDelta: before,
		PidsCurrent:      0,
	})
	appendViolations(&rec, policy.EvaluateCommand(rec.Spec, 0))
	return o.transition(ctx, &rec, spec.StateReady, "operax", "workspace detached")
}

func (o *Orchestrator) DestroyWorkspace(ctx context.Context, id, actor, message string) error {
	unlock, err := o.lockWorkspace(id)
	if err != nil {
		return err
	}
	defer unlock()

	rec, err := o.store.Load(ctx, id)
	if err != nil {
		return err
	}
	if rec.Workspace.State == spec.StateDestroyed {
		return nil
	}

	if err := o.transition(ctx, &rec, spec.StateExpiring, actor, message); err != nil {
		return err
	}
	if rec.Spec.SnapshotOnExit {
		if _, err := o.SnapshotWorkspace(ctx, id); err != nil {
			return err
		}
		rec, err = o.store.Load(ctx, id)
		if err != nil {
			return err
		}
	}
	if err := o.provisioner.Destroy(ctx, &rec.Workspace); err != nil {
		return err
	}
	if err := o.resources.Remove(id); err != nil {
		return err
	}
	return o.transition(ctx, &rec, spec.StateDestroyed, actor, "workspace destroyed")
}

func (o *Orchestrator) SnapshotWorkspace(ctx context.Context, id string) (string, error) {
	unlock, err := o.lockWorkspace(id)
	if err != nil {
		return "", err
	}
	defer unlock()

	rec, err := o.store.Load(ctx, id)
	if err != nil {
		return "", err
	}
	reader, path, err := o.provisioner.Snapshot(ctx, &rec.Workspace)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, reader)

	rec.Workspace.SnapshotPath = path
	rec.Audit.SnapshotPath = path
	rec.Audit.UpdatedAt = time.Now().UTC()
	rec.Audit.LifecycleEvents = append(rec.Audit.LifecycleEvents, spec.LifecycleEvent{
		WorkspaceID: rec.Workspace.ID,
		From:        rec.Workspace.State,
		To:          rec.Workspace.State,
		Actor:       "operax",
		Message:     "workspace snapshot captured",
		At:          rec.Audit.UpdatedAt,
	})
	if err := o.persistRecord(ctx, rec); err != nil {
		return "", err
	}
	return path, nil
}

func (o *Orchestrator) SuspendWorkspace(ctx context.Context, id string) error {
	unlock, err := o.lockWorkspace(id)
	if err != nil {
		return err
	}
	defer unlock()

	rec, err := o.store.Load(ctx, id)
	if err != nil {
		return err
	}
	return o.transition(ctx, &rec, spec.StateSuspended, "operax", "workspace suspended")
}

func (o *Orchestrator) RestoreWorkspace(ctx context.Context, wsSpec spec.WorkspaceSpec) (*spec.StateRecord, error) {
	if wsSpec.RestoreSnapshot == "" {
		return nil, errors.New("restore snapshot path is required")
	}
	return o.CreateWorkspace(ctx, wsSpec)
}

func (o *Orchestrator) Metrics(ctx context.Context, id string) (*spec.ResourceMetrics, error) {
	return o.resources.Metrics(id)
}

func (o *Orchestrator) Audit(ctx context.Context, id string) (*spec.AuditRecord, error) {
	rec, err := o.store.Load(ctx, id)
	if err != nil {
		return nil, err
	}
	return &rec.Audit, nil
}

func (o *Orchestrator) Get(ctx context.Context, id string) (*spec.StateRecord, error) {
	rec, err := o.store.Load(ctx, id)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (o *Orchestrator) List(ctx context.Context) ([]spec.StateRecord, error) {
	return o.store.List(ctx)
}

// ListPaginated returns a paginated subset of workspace state records.
// This enables efficient browsing of large workload sets by loading only the needed records.
// Use this instead of List() when dealing with many workspaces to avoid memory exhaustion.
func (o *Orchestrator) ListPaginated(ctx context.Context, page pagination.PageInfo) (pagination.Result[spec.StateRecord], error) {
	return o.store.ListPaginated(ctx, page)
}

// RunTTLReaper starts the TTL reaper loop (deprecated: use NewTTLReaper().Run() instead).
// This method is kept for backward compatibility.
func (o *Orchestrator) RunTTLReaper(ctx context.Context) error {
	r := o.NewTTLReaper()
	return r.Run(ctx)
}

// ReapOnce performs a single reap cycle (deprecated: use NewTTLReaper().ReapOnce() instead).
// This method is kept for backward compatibility.
func (o *Orchestrator) ReapOnce(ctx context.Context) error {
	r := o.NewTTLReaper()
	return r.ReapOnce(ctx)
}

func appendViolations(rec *spec.StateRecord, violations []spec.SeccompViolation) {
	now := time.Now().UTC()
	for i := range violations {
		violations[i].WorkspaceID = rec.Workspace.ID
		violations[i].At = now
	}
	rec.Audit.SeccompViolations = append(rec.Audit.SeccompViolations, violations...)
	rec.Audit.UpdatedAt = now
}

func dirSize(root string) (int64, error) {
	var size int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func minPositive(limit, current int64) int64 {
	if current <= 0 {
		return 0
	}
	if limit > 0 && current > limit {
		return limit
	}
	return current
}

func (o *Orchestrator) transition(ctx context.Context, rec *spec.StateRecord, next spec.WorkspaceState, actor, message string) error {
	now := time.Now().UTC()
	event := spec.LifecycleEvent{
		WorkspaceID: rec.Workspace.ID,
		From:        rec.Workspace.State,
		To:          next,
		Actor:       actor,
		Message:     message,
		At:          now,
	}

	rec.Workspace.State = next
	rec.Workspace.UpdatedAt = now
	rec.Audit.LastTransitionState = next
	rec.Audit.UpdatedAt = now
	rec.Audit.LifecycleEvents = append(rec.Audit.LifecycleEvents, event)

	if metrics, err := o.resources.Metrics(rec.Workspace.ID); err == nil {
		rec.Metrics = *metrics
		rec.Audit.ResourceReport = *metrics
	}

	return o.persistRecord(ctx, *rec)
}

func (o *Orchestrator) persistRecord(ctx context.Context, rec spec.StateRecord) error {
	if o.journal == nil {
		if err := o.store.Save(ctx, rec); err != nil {
			return err
		}
		return o.audit.WriteRecord(ctx, rec.Audit)
	}
	statePath, auditPath := "", ""
	if fs, ok := o.store.(*store.FileStore); ok {
		p, _ := fs.RecordPath(rec.Workspace.ID)
		statePath = p
	}
	if as, ok := o.audit.(*audit.FileSink); ok {
		auditPath = as.AuditPath(rec.Workspace.ID)
	}
	token, err := o.journal.Begin(journal.Entry{
		WorkspaceID: rec.Workspace.ID,
		StatePath:   statePath,
		AuditPath:   auditPath,
	})
	if err != nil {
		return err
	}
	if err := o.store.Save(ctx, rec); err != nil {
		return err
	}
	if err := o.audit.WriteRecord(ctx, rec.Audit); err != nil {
		return err
	}
	return o.journal.Commit(token)
}

func (o *Orchestrator) lockWorkspace(id string) (func(), error) {
	if o.wsLocks == nil {
		return func() {}, nil
	}
	return o.wsLocks.Lock(id)
}
