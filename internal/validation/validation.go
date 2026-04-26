package validation

import (
	"fmt"
	"net"

	"operax/internal/errors"
)

// ResourceLimits defines minimum and maximum resource constraints.
const (
	// Memory limits (in bytes)
	MinMemBytes = 64 * 1024 * 1024         // 64 MiB minimum
	MaxMemBytes = 256 * 1024 * 1024 * 1024 // 256 GiB maximum

	// CPU quota (as percentage * 10000, e.g., 50% = 500000)
	MinCPUQuota = 10000    // 1%
	MaxCPUQuota = 10000000 // 1000%

	// Process limits
	MinPidsMax = 1
	MaxPidsMax = 4194304 // Linux kernel max

	// I/O bandwidth limits (bytes per second)
	MinIOBps = 1024                      // 1 KiB/s
	MaxIOBps = 1024 * 1024 * 1024 * 1024 // 1 TiB/s

	// TTL limits
	MinTTLSeconds = 1
	MaxTTLSeconds = 86400 * 365 // 1 year
)

// ValidateCPUQuota validates that CPU quota is within acceptable bounds.
func ValidateCPUQuota(cpuQuota int64) error {
	if cpuQuota < MinCPUQuota {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "cpu_quota",
			Message: fmt.Sprintf("must be at least %d (%.1f%%)", MinCPUQuota, float64(MinCPUQuota)/10000),
		}
	}
	if cpuQuota > MaxCPUQuota {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "cpu_quota",
			Message: fmt.Sprintf("must not exceed %d (%.1f%%)", MaxCPUQuota, float64(MaxCPUQuota)/10000),
		}
	}
	return nil
}

// ValidateMemLimit validates that memory limit is within acceptable bounds.
func ValidateMemLimit(memBytes int64) error {
	if memBytes < MinMemBytes {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "mem_limit_bytes",
			Message: fmt.Sprintf("must be at least %d bytes (%.1f MiB)", MinMemBytes, float64(MinMemBytes)/(1024*1024)),
		}
	}
	if memBytes > MaxMemBytes {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "mem_limit_bytes",
			Message: fmt.Sprintf("must not exceed %d bytes (%.1f GiB)", MaxMemBytes, float64(MaxMemBytes)/(1024*1024*1024)),
		}
	}
	return nil
}

// ValidatePidsMax validates that process limit is within acceptable bounds.
func ValidatePidsMax(pidsMax int64) error {
	if pidsMax < MinPidsMax {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "pids_max",
			Message: fmt.Sprintf("must be at least %d", MinPidsMax),
		}
	}
	if pidsMax > MaxPidsMax {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "pids_max",
			Message: fmt.Sprintf("must not exceed %d", MaxPidsMax),
		}
	}
	return nil
}

// ValidateIOBandwidth validates that I/O bandwidth limits are within acceptable bounds.
func ValidateIOBandwidth(ioBps int64, fieldName string) error {
	if ioBps <= 0 {
		return nil // 0 means unlimited
	}
	if ioBps < MinIOBps {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   fieldName,
			Message: fmt.Sprintf("must be at least %d (%.1f KiB/s) or 0 for unlimited", MinIOBps, float64(MinIOBps)/1024),
		}
	}
	if ioBps > MaxIOBps {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   fieldName,
			Message: fmt.Sprintf("must not exceed %d (%.1f TiB/s)", MaxIOBps, float64(MaxIOBps)/(1024*1024*1024*1024)),
		}
	}
	return nil
}

// ValidateCIDR validates that a CIDR block is valid.
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "allowed_cidrs",
			Message: fmt.Sprintf("invalid CIDR %q: %v", cidr, err),
		}
	}
	return nil
}

// ValidateCIDRs validates a list of CIDR blocks.
func ValidateCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		if err := ValidateCIDR(cidr); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTTLSeconds validates that TTL is within acceptable bounds.
func ValidateTTLSeconds(ttlSeconds int64) error {
	if ttlSeconds < MinTTLSeconds {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "ttl",
			Message: fmt.Sprintf("must be at least %d seconds", MinTTLSeconds),
		}
	}
	if ttlSeconds > MaxTTLSeconds {
		return &errors.ErrInvalidWorkspaceSpec{
			Field:   "ttl",
			Message: fmt.Sprintf("must not exceed %d seconds (1 year)", MaxTTLSeconds),
		}
	}
	return nil
}

// ValidateAllResources runs all resource validations.
func ValidateAllResources(cpuQuota, memBytes, pidsMax, ioReadBps, ioWriteBps, ttlSeconds int64) error {
	if err := ValidateCPUQuota(cpuQuota); err != nil {
		return err
	}
	if err := ValidateMemLimit(memBytes); err != nil {
		return err
	}
	if err := ValidatePidsMax(pidsMax); err != nil {
		return err
	}
	if err := ValidateIOBandwidth(ioReadBps, "io_read_bps"); err != nil {
		return err
	}
	if err := ValidateIOBandwidth(ioWriteBps, "io_write_bps"); err != nil {
		return err
	}
	if err := ValidateTTLSeconds(ttlSeconds); err != nil {
		return err
	}
	return nil
}
