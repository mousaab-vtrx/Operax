//go:build !linux

package provision

import (
	"fmt"
)

func KernelBackendAvailable() bool {
	return false
}

func NewKernelProvisioner(string, string, string) (*LocalProvisioner, error) {
	return nil, fmt.Errorf("kernel backend is only available on linux")
}

func NewKernelResourceManager(string) (*StaticResourceManager, error) {
	return nil, fmt.Errorf("kernel backend is only available on linux")
}
