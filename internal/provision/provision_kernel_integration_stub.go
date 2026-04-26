//go:build !linux

package provision

import "testing"

// Stub implementations for non-Linux systems

func skipKernelBackendIntegrationTests(t *testing.T) bool {
	t.Skip("kernel backend is linux-only")
	return true
}

func TestKernelBackendAvailability(t *testing.T) {
	t.Log("kernel backend not available on non-Linux")
}

func TestKernelProvisionerCreate(t *testing.T) {
	skipKernelBackendIntegrationTests(t)
}
