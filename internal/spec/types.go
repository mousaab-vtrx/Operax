package spec

import (
	"encoding/json"
	"fmt"
	"time"

	"operax/internal/errors"
	"operax/internal/validation"
)

type WorkspaceState string

const (
	StatePending      WorkspaceState = "PENDING"
	StateProvisioning WorkspaceState = "PROVISIONING"
	StateReady        WorkspaceState = "READY"
	StateAttached     WorkspaceState = "ATTACHED"
	StateSuspended    WorkspaceState = "SUSPENDED"
	StateExpiring     WorkspaceState = "EXPIRING"
	StateDestroyed    WorkspaceState = "DESTROYED"
	StateRejected     WorkspaceState = "REJECTED"
	StateFailed       WorkspaceState = "FAILED"
)

type NetworkPolicy string

const (
	NetworkNone      NetworkPolicy = "none"
	NetworkAllowlist NetworkPolicy = "allowlist"
	NetworkOpen      NetworkPolicy = "open"
)

type WorkspaceSpec struct {
	ID               string        `json:"id"`
	TenantID         string        `json:"tenant_id"`
	TTL              time.Duration `json:"ttl"`
	CPUQuota         int64         `json:"cpu_quota"`
	CPUPeriod        int64         `json:"cpu_period"`
	MemLimitBytes    int64         `json:"mem_limit_bytes"`
	IOReadBps        int64         `json:"io_read_bps"`
	IOWriteBps       int64         `json:"io_write_bps"`
	PidsMax          int64         `json:"pids_max"`
	NetworkPolicy    NetworkPolicy `json:"network_policy"`
	AllowedCIDRs     []string      `json:"allowed_cidrs,omitempty"`
	SeccompProfileID string        `json:"seccomp_profile_id"`
	LowerDir         string        `json:"lower_dir"`
	Command          []string      `json:"command"`
	SnapshotOnExit   bool          `json:"snapshot_on_exit"`
	RestoreSnapshot  string        `json:"restore_snapshot,omitempty"`
	Backend          string        `json:"backend,omitempty"`
}

func (s WorkspaceSpec) Validate() error {
	// Basic field presence checks
	if s.ID == "" {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "id",
			Message: "workspace ID is required",
		}
	}
	if s.TenantID == "" {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "tenant_id",
			Message: "tenant ID is required",
		}
	}
	if s.TTL <= 0 {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "ttl",
			Message: "TTL must be greater than zero",
		}
	}
	if s.CPUPeriod == 0 {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "cpu_period",
			Message: "CPU period must be greater than zero",
		}
	}
	if len(s.Command) == 0 {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "command",
			Message: "command is required",
		}
	}
	if s.NetworkPolicy == "" {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "network_policy",
			Message: "network policy is required",
		}
	}
	if s.SeccompProfileID == "" {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "seccomp_profile_id",
			Message: "seccomp profile ID is required",
		}
	}

	// Validate network policy
	validPolicies := []NetworkPolicy{NetworkNone, NetworkAllowlist, NetworkOpen}
	validPolicy := false
	for _, p := range validPolicies {
		if s.NetworkPolicy == p {
			validPolicy = true
			break
		}
	}
	if !validPolicy {
		return &errors.ErrPolicyViolation{
			Field:   "network_policy",
			Message: fmt.Sprintf("unsupported network policy %q", s.NetworkPolicy),
		}
	}

	// Validate CIDRs if using allowlist
	if s.NetworkPolicy == NetworkAllowlist {
		if len(s.AllowedCIDRs) == 0 {
			return &errors.ErrPolicyViolation{
				Field:   "allowed_cidrs",
				Message: "allowlist network policy requires at least one allowed CIDR",
			}
		}
		if err := validation.ValidateCIDRs(s.AllowedCIDRs); err != nil {
			return err
		}
	}

	// Validate resource bounds
	ttlSeconds := int64(s.TTL.Seconds())
	if err := validation.ValidateAllResources(
		s.CPUQuota,
		s.MemLimitBytes,
		s.PidsMax,
		s.IOReadBps,
		s.IOWriteBps,
		ttlSeconds,
	); err != nil {
		return err
	}

	return nil
}

type ResourceLimits struct {
	CPUQuota      int64 `json:"cpu_quota"`
	CPUPeriod     int64 `json:"cpu_period"`
	MemLimitBytes int64 `json:"mem_limit_bytes"`
	IOReadBps     int64 `json:"io_read_bps"`
	IOWriteBps    int64 `json:"io_write_bps"`
	PidsMax       int64 `json:"pids_max"`
}

type ResourceMetrics struct {
	CPUQuotaMicros   int64     `json:"cpu_quota_micros"`
	MemoryCurrent    int64     `json:"memory_current"`
	MemoryPeak       int64     `json:"memory_peak"`
	IOReadBytes      int64     `json:"io_read_bytes"`
	IOWriteBytes     int64     `json:"io_write_bytes"`
	PidsCurrent      int64     `json:"pids_current"`
	PidsPeak         int64     `json:"pids_peak"`
	ThermalScore     float64   `json:"thermal_score,omitempty"`
	ThermalState     string    `json:"thermal_state,omitempty"`
	ThermalThrottled bool      `json:"thermal_throttled,omitempty"`
	LastUpdated      time.Time `json:"last_updated"`
	EnforcementNotes []string  `json:"enforcement_notes,omitempty"`
}

type ResourceObservation struct {
	MemoryCurrent     int64
	IOReadBytesDelta  int64
	IOWriteBytesDelta int64
	PidsCurrent       int64
}

type Workspace struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	State          WorkspaceState `json:"state"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	RootDir        string         `json:"root_dir"`
	UpperDir       string         `json:"upper_dir"`
	WorkDir        string         `json:"work_dir"`
	MergedDir      string         `json:"merged_dir"`
	TranscriptPath string         `json:"transcript_path"`
	AuditPath      string         `json:"audit_path"`
	SnapshotPath   string         `json:"snapshot_path,omitempty"`
	NetworkPlan    string         `json:"network_plan,omitempty"`
	SeccompPlan    string         `json:"seccomp_plan,omitempty"`
	Backend        string         `json:"backend,omitempty"`
	InitPID        int            `json:"init_pid,omitempty"`
	CgroupPath     string         `json:"cgroup_path,omitempty"`
	HostVeth       string         `json:"host_veth,omitempty"`
	GuestVeth      string         `json:"guest_veth,omitempty"`
	BridgeName     string         `json:"bridge_name,omitempty"`
	NFTTable       string         `json:"nft_table,omitempty"`
	NFTNatTable    string         `json:"nft_nat_table,omitempty"`
	HostAddress    string         `json:"host_address,omitempty"`
	GuestAddress   string         `json:"guest_address,omitempty"`
}

// IsExpired returns true if the workspace TTL has elapsed
func (w *Workspace) IsExpired() bool {
	return time.Now().UTC().After(w.ExpiresAt)
}

// IsExpiringSoon returns true if workspace expires within specified duration
func (w *Workspace) IsExpiringSoon(d time.Duration) bool {
	return time.Now().UTC().Add(d).After(w.ExpiresAt)
}

// TimeRemaining returns duration until expiration (0 if already expired)
func (w *Workspace) TimeRemaining() time.Duration {
	remaining := time.Until(w.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

type LifecycleEvent struct {
	WorkspaceID string         `json:"workspace_id"`
	From        WorkspaceState `json:"from"`
	To          WorkspaceState `json:"to"`
	Actor       string         `json:"actor"`
	Message     string         `json:"message"`
	At          time.Time      `json:"at"`
}

type SeccompViolation struct {
	WorkspaceID string    `json:"workspace_id"`
	Syscall     string    `json:"syscall"`
	Args        []uint64  `json:"args"`
	Result      string    `json:"result"`
	PID         int       `json:"pid"`
	At          time.Time `json:"at"`
}

type AuditRecord struct {
	WorkspaceID         string             `json:"workspace_id"`
	TenantID            string             `json:"tenant_id"`
	TranscriptPath      string             `json:"transcript_path"`
	ResourceReport      ResourceMetrics    `json:"resource_report"`
	SeccompViolations   []SeccompViolation `json:"seccomp_violations"`
	LifecycleEvents     []LifecycleEvent   `json:"lifecycle_events"`
	EgressPolicy        NetworkPolicy      `json:"egress_policy"`
	SeccompProfileID    string             `json:"seccomp_profile_id"`
	SnapshotPath        string             `json:"snapshot_path,omitempty"`
	LastTransitionState WorkspaceState     `json:"last_transition_state"`
	UpdatedAt           time.Time          `json:"updated_at"`
}

type StateRecord struct {
	Spec      WorkspaceSpec   `json:"spec"`
	Workspace Workspace       `json:"workspace"`
	Metrics   ResourceMetrics `json:"metrics"`
	Audit     AuditRecord     `json:"audit"`
}

func Pretty(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(data)
}
