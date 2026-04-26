package metrics

import (
	"sync"
	"time"
)

// Metrics tracks operational and resource metrics for operax.
type Metrics struct {
	mu                  sync.RWMutex
	workspacesCreated   uint64
	workspacesExpired   uint64
	workspacesDestroyed uint64
	workspacesFailed    uint64
	workspaceDurations  []time.Duration
	resourceViolations  map[string]uint64 // resource type -> count
	snapshotsCreated    uint64
	snapshotsRestored   uint64
	snapshotsFailed     uint64
	workspacesByState   map[string]uint64 // state -> count
}

// New creates a new Metrics instance.
func New() *Metrics {
	return &Metrics{
		resourceViolations: make(map[string]uint64),
		workspacesByState:  make(map[string]uint64),
		workspaceDurations: make([]time.Duration, 0),
	}
}

// RecordWorkspaceCreated increments the count of created workspaces.
func (m *Metrics) RecordWorkspaceCreated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workspacesCreated++
}

// RecordWorkspaceExpired increments the count of expired workspaces.
func (m *Metrics) RecordWorkspaceExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workspacesExpired++
}

// RecordWorkspaceDestroyed increments the count of destroyed workspaces.
func (m *Metrics) RecordWorkspaceDestroyed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workspacesDestroyed++
}

// RecordWorkspaceFailed increments the count of failed workspaces.
func (m *Metrics) RecordWorkspaceFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workspacesFailed++
}

// RecordWorkspaceDuration records the duration of a workspace lifetime.
func (m *Metrics) RecordWorkspaceDuration(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workspaceDurations = append(m.workspaceDurations, duration)
}

// RecordResourceViolation records a resource limit violation.
func (m *Metrics) RecordResourceViolation(resourceType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resourceViolations[resourceType]++
}

// RecordSnapshotCreated increments the count of created snapshots.
func (m *Metrics) RecordSnapshotCreated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotsCreated++
}

// RecordSnapshotRestored increments the count of restored snapshots.
func (m *Metrics) RecordSnapshotRestored() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotsRestored++
}

// RecordSnapshotFailed increments the count of failed snapshots.
func (m *Metrics) RecordSnapshotFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotsFailed++
}

// RecordWorkspaceStateTransition records a workspace state change.
func (m *Metrics) RecordWorkspaceStateTransition(toState string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workspacesByState[toState]++
}

// GetWorkspacesCreated returns the total number of workspaces created.
func (m *Metrics) GetWorkspacesCreated() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.workspacesCreated
}

// GetWorkspacesExpired returns the total number of expired workspaces.
func (m *Metrics) GetWorkspacesExpired() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.workspacesExpired
}

// GetWorkspacesDestroyed returns the total number of destroyed workspaces.
func (m *Metrics) GetWorkspacesDestroyed() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.workspacesDestroyed
}

// GetWorkspacesFailed returns the total number of failed workspaces.
func (m *Metrics) GetWorkspacesFailed() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.workspacesFailed
}

// GetResourceViolations returns the count of violations by resource type.
func (m *Metrics) GetResourceViolations() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]uint64)
	for k, v := range m.resourceViolations {
		result[k] = v
	}
	return result
}

// GetSnapshotsCreated returns the total number of created snapshots.
func (m *Metrics) GetSnapshotsCreated() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotsCreated
}

// GetSnapshotsRestored returns the total number of restored snapshots.
func (m *Metrics) GetSnapshotsRestored() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotsRestored
}

// GetAverageDuration returns the average workspace lifetime duration.
func (m *Metrics) GetAverageDuration() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.workspaceDurations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range m.workspaceDurations {
		total += d
	}
	return total / time.Duration(len(m.workspaceDurations))
}

// GetWorkspacesByState returns the count of workspaces by state.
func (m *Metrics) GetWorkspacesByState() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]uint64)
	for k, v := range m.workspacesByState {
		result[k] = v
	}
	return result
}

// Summary returns a human-readable summary of metrics.
func (m *Metrics) Summary() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resourceViolsCopy := make(map[string]uint64)
	for k, v := range m.resourceViolations {
		resourceViolsCopy[k] = v
	}

	statesCopy := make(map[string]uint64)
	for k, v := range m.workspacesByState {
		statesCopy[k] = v
	}

	avgDuration := time.Duration(0)
	if len(m.workspaceDurations) > 0 {
		var total time.Duration
		for _, d := range m.workspaceDurations {
			total += d
		}
		avgDuration = total / time.Duration(len(m.workspaceDurations))
	}

	return map[string]interface{}{
		"workspaces_created":   m.workspacesCreated,
		"workspaces_expired":   m.workspacesExpired,
		"workspaces_destroyed": m.workspacesDestroyed,
		"workspaces_failed":    m.workspacesFailed,
		"snapshots_created":    m.snapshotsCreated,
		"snapshots_restored":   m.snapshotsRestored,
		"snapshots_failed":     m.snapshotsFailed,
		"average_duration":     avgDuration.String(),
		"resource_violations":  resourceViolsCopy,
		"workspaces_by_state":  statesCopy,
	}
}
