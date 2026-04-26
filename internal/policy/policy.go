package policy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"operax/internal/spec"
)

type SeccompProfile struct {
	ID              string
	DefaultAction   string
	AllowedSyscalls []string
	DeniedSyscalls  []string
	Description     string
}

var profiles = map[string]SeccompProfile{
	"default": {
		ID:            "default",
		DefaultAction: "SCMP_ACT_ERRNO",
		Description:   "General-purpose developer workspace profile.",
		AllowedSyscalls: []string{
			"access", "arch_prctl", "brk", "chdir", "clock_gettime", "clone", "close",
			"dup", "dup2", "dup3", "epoll_create1", "epoll_ctl", "epoll_wait", "execve",
			"exit", "exit_group", "fcntl", "fstat", "futex", "getcwd", "getdents64",
			"getegid", "geteuid", "getgid", "getpid", "getppid", "getrandom", "gettid",
			"getuid", "ioctl", "lseek", "lstat", "madvise", "mmap", "mprotect", "munmap",
			"nanosleep", "newfstatat", "openat", "pipe2", "pread64", "prlimit64", "read",
			"readlink", "readlinkat", "recvfrom", "rt_sigaction", "rt_sigprocmask",
			"rt_sigreturn", "sched_getaffinity", "select", "sendto", "set_robust_list",
			"set_tid_address", "sigaltstack", "socket", "stat", "statfs", "sysinfo",
			"uname", "wait4", "write", "writev", "rseq",
		},
		DeniedSyscalls: []string{"mount", "umount2", "pivot_root", "ptrace", "perf_event_open", "kexec_load", "reboot", "syslog", "setuid", "setgid"},
	},
	"strict": {
		ID:            "strict",
		DefaultAction: "SCMP_ACT_ERRNO",
		Description:   "Restricted profile that blocks tracing and namespace manipulation.",
		AllowedSyscalls: []string{
			"access", "arch_prctl", "brk", "chdir", "clock_gettime", "close", "dup",
			"dup2", "dup3", "epoll_create1", "epoll_ctl", "epoll_wait", "execve", "exit",
			"exit_group", "fcntl", "fstat", "futex", "getcwd", "getdents64", "getegid",
			"geteuid", "getgid", "getpid", "getppid", "getrandom", "gettid", "getuid",
			"ioctl", "lseek", "lstat", "madvise", "mmap", "mprotect", "munmap",
			"nanosleep", "newfstatat", "openat", "pipe2", "pread64", "prlimit64", "read",
			"readlink", "readlinkat", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
			"sched_getaffinity", "set_robust_list", "set_tid_address", "sigaltstack",
			"stat", "statfs", "sysinfo", "uname", "wait4", "write", "writev", "rseq",
		},
		DeniedSyscalls: []string{"mount", "umount2", "pivot_root", "ptrace", "perf_event_open", "kexec_load", "reboot", "syslog", "setuid", "setgid", "clone", "unshare"},
	},
}

func ValidateWorkspaceSpec(wsSpec spec.WorkspaceSpec) error {
	if !slices.Contains([]spec.NetworkPolicy{spec.NetworkNone, spec.NetworkAllowlist, spec.NetworkOpen}, wsSpec.NetworkPolicy) {
		return fmt.Errorf("unsupported network policy %q", wsSpec.NetworkPolicy)
	}
	if wsSpec.NetworkPolicy == spec.NetworkAllowlist && len(wsSpec.AllowedCIDRs) == 0 {
		return errors.New("allowlist network policy requires at least one allowed CIDR")
	}
	for _, cidr := range wsSpec.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid allowed cidr %q: %w", cidr, err)
		}
	}
	if _, ok := profiles[wsSpec.SeccompProfileID]; !ok {
		return fmt.Errorf("unknown seccomp profile %q", wsSpec.SeccompProfileID)
	}
	return nil
}

func ExplainWorkspaceSpec(wsSpec spec.WorkspaceSpec) []string {
	notes := []string{
		fmt.Sprintf("network policy=%s", wsSpec.NetworkPolicy),
		fmt.Sprintf("seccomp profile=%s", wsSpec.SeccompProfileID),
	}
	switch wsSpec.NetworkPolicy {
	case spec.NetworkAllowlist:
		notes = append(notes, fmt.Sprintf("allowlist destinations=%s", strings.Join(wsSpec.AllowedCIDRs, ",")))
	case spec.NetworkNone:
		notes = append(notes, "egress is fully blocked")
	case spec.NetworkOpen:
		notes = append(notes, "egress is unrestricted")
	}
	if profile, ok := profiles[wsSpec.SeccompProfileID]; ok {
		notes = append(notes, fmt.Sprintf("denied syscalls=%s", strings.Join(profile.DeniedSyscalls, ",")))
	}
	return notes
}

func ResolveSeccompProfile(id string) (SeccompProfile, error) {
	profile, ok := profiles[id]
	if !ok {
		return SeccompProfile{}, fmt.Errorf("unknown seccomp profile %q", id)
	}
	return profile, nil
}

func WritePlans(root string, wsSpec spec.WorkspaceSpec) (networkPlanPath, seccompPlanPath string, err error) {
	networkPlanPath = filepath.Join(root, "network.policy")
	seccompPlanPath = filepath.Join(root, "seccomp.policy")

	profile, err := ResolveSeccompProfile(wsSpec.SeccompProfileID)
	if err != nil {
		return "", "", err
	}

	networkBody := buildNetworkPlan(wsSpec)
	if err := os.WriteFile(networkPlanPath, []byte(networkBody), 0o644); err != nil {
		return "", "", err
	}

	seccompBody := buildSeccompPlan(profile)
	if err := os.WriteFile(seccompPlanPath, []byte(seccompBody), 0o644); err != nil {
		return "", "", err
	}
	return networkPlanPath, seccompPlanPath, nil
}

func EvaluateCommand(wsSpec spec.WorkspaceSpec, pid int) []spec.SeccompViolation {
	profile, err := ResolveSeccompProfile(wsSpec.SeccompProfileID)
	if err != nil {
		return nil
	}
	commandLine := strings.Join(wsSpec.Command, " ")
	var violations []spec.SeccompViolation
	for _, denied := range profile.DeniedSyscalls {
		if strings.Contains(commandLine, denied) || strings.Contains(commandLine, "strace") && denied == "ptrace" {
			violations = append(violations, spec.SeccompViolation{
				WorkspaceID: wsSpec.ID,
				Syscall:     denied,
				Args:        []uint64{0, 0, 0, 0},
				Result:      "EPERM",
				PID:         pid,
			})
		}
	}
	return violations
}

func buildNetworkPlan(wsSpec spec.WorkspaceSpec) string {
	switch wsSpec.NetworkPolicy {
	case spec.NetworkNone:
		return "table inet operax {\n  chain egress {\n    oifname \"ws-host\" drop\n  }\n}\n"
	case spec.NetworkAllowlist:
		return fmt.Sprintf("table inet operax {\n  chain egress {\n    ip daddr != { %s } drop\n  }\n}\n", strings.Join(wsSpec.AllowedCIDRs, ", "))
	default:
		return "table inet operax {\n  chain egress {\n    accept\n  }\n}\n"
	}
}

func buildSeccompPlan(profile SeccompProfile) string {
	return fmt.Sprintf(
		"profile=%s\ndefault_action=%s\nallow=%s\ndeny=%s\n",
		profile.ID,
		profile.DefaultAction,
		strings.Join(profile.AllowedSyscalls, ","),
		strings.Join(profile.DeniedSyscalls, ","),
	)
}
