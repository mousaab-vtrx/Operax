package errors

import (
	"errors"
	"fmt"
)

// ErrWorkspaceNotFound is returned when a workspace cannot be found.
type ErrWorkspaceNotFound struct {
	WorkspaceID string
}

func (e *ErrWorkspaceNotFound) Error() string {
	return fmt.Sprintf("workspace not found: %s", e.WorkspaceID)
}

// ErrWorkspaceStateCorrupted is returned when workspace state file is invalid or unreadable.
type ErrWorkspaceStateCorrupted struct {
	WorkspaceID string
	Err         error
}

func (e *ErrWorkspaceStateCorrupted) Error() string {
	return fmt.Sprintf("workspace state corrupted: %s (details: %v)", e.WorkspaceID, e.Err)
}

// ErrInvalidWorkspaceSpec is returned when a workspace specification fails validation.
// This includes missing required fields, invalid values, or values outside acceptable bounds.
type ErrInvalidWorkspaceSpec struct {
	Field   string // The field that failed validation
	Message string // Detailed message about the validation failure
}

func (e *ErrInvalidWorkspaceSpec) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("invalid workspace spec: %s - %s", e.Field, e.Message)
	}
	return fmt.Sprintf("invalid workspace spec: %s", e.Message)
}

// ErrResourcesNotApplied is returned when resource limits cannot be applied to a workspace.
// This typically indicates a kernel or cgroup configuration issue.
type ErrResourcesNotApplied struct {
	WorkspaceID string
	Resource    string // "cpu", "memory", "io", "pids"
	Err         error
}

func (e *ErrResourcesNotApplied) Error() string {
	return fmt.Sprintf("failed to apply %s limits to workspace %s: %v", e.Resource, e.WorkspaceID, e.Err)
}

// ErrProvisioningFailed is returned when workspace provisioning fails at any stage.
type ErrProvisioningFailed struct {
	WorkspaceID string
	Stage       string // "create", "attach", "destroy", "snapshot", "restore"
	Err         error
}

func (e *ErrProvisioningFailed) Error() string {
	return fmt.Sprintf("provisioning failed at stage '%s' for workspace %s: %v", e.Stage, e.WorkspaceID, e.Err)
}

// ErrPolicyViolation is returned when workspace specification violates security or resource policy.
type ErrPolicyViolation struct {
	Field   string // The policy field that was violated
	Message string // Description of the policy violation
}

func (e *ErrPolicyViolation) Error() string {
	return fmt.Sprintf("policy violation: %s - %s", e.Field, e.Message)
}

// ErrWorkspaceStateTransitionInvalid is returned when state transition is not allowed.
type ErrWorkspaceStateTransitionInvalid struct {
	CurrentState string
	TargetState  string
}

func (e *ErrWorkspaceStateTransitionInvalid) Error() string {
	return fmt.Sprintf("invalid state transition: %s -> %s", e.CurrentState, e.TargetState)
}

// ErrWorkspaceAlreadyExists is returned when attempting to create a workspace with duplicate ID.
type ErrWorkspaceAlreadyExists struct {
	WorkspaceID string
}

func (e *ErrWorkspaceAlreadyExists) Error() string {
	return fmt.Sprintf("workspace already exists: %s", e.WorkspaceID)
}

// ErrPermissionDenied is returned when operation lacks required permissions (e.g., requires root).
type ErrPermissionDenied struct {
	Operation string // The operation that requires permissions
	Reason    string // Why permission was denied (e.g., "requires root")
}

func (e *ErrPermissionDenied) Error() string {
	return fmt.Sprintf("permission denied: %s (%s)", e.Operation, e.Reason)
}

// Is helpers for error type checking
var (
	// IsNotFound returns true if err is a not-found error.
	IsNotFound = func(err error) bool {
		var e *ErrWorkspaceNotFound
		return errors.As(err, &e)
	}

	// IsStateCorrupted returns true if err is a state corruption error.
	IsStateCorrupted = func(err error) bool {
		var e *ErrWorkspaceStateCorrupted
		return errors.As(err, &e)
	}

	// IsInvalidSpec returns true if err is a specification validation error.
	IsInvalidSpec = func(err error) bool {
		var e *ErrInvalidWorkspaceSpec
		return errors.As(err, &e)
	}

	// IsPolicyViolation returns true if err is a policy violation.
	IsPolicyViolation = func(err error) bool {
		var e *ErrPolicyViolation
		return errors.As(err, &e)
	}
)
