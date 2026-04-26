//go:build linux

package seccomp

import (
	"fmt"
	"syscall"
	"unsafe"

	"operax/internal/policy"
)

const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfK   = 0x00
	bpfRET = 0x06

	prSetNoNewPrivs       = 38
	prSetSeccomp          = 22
	seccompModeFilter     = 2
	seccompRetAllow       = 0x7fff0000
	seccompRetErrno       = 0x00050000
	auditArchAMD64        = 0xc000003e
	seccompDataArchOffset = 4
	seccompDataNR         = 0
	sysGetrandomAMD64     = 318
	sysRseqAMD64          = 334
)

var syscallNumbers = map[string]uint32{
	"access":            syscall.SYS_ACCESS,
	"arch_prctl":        syscall.SYS_ARCH_PRCTL,
	"read":              syscall.SYS_READ,
	"write":             syscall.SYS_WRITE,
	"writev":            syscall.SYS_WRITEV,
	"openat":            syscall.SYS_OPENAT,
	"close":             syscall.SYS_CLOSE,
	"mmap":              syscall.SYS_MMAP,
	"mprotect":          syscall.SYS_MPROTECT,
	"munmap":            syscall.SYS_MUNMAP,
	"brk":               syscall.SYS_BRK,
	"futex":             syscall.SYS_FUTEX,
	"fcntl":             syscall.SYS_FCNTL,
	"ioctl":             syscall.SYS_IOCTL,
	"pread64":           syscall.SYS_PREAD64,
	"execve":            syscall.SYS_EXECVE,
	"clone":             syscall.SYS_CLONE,
	"wait4":             syscall.SYS_WAIT4,
	"exit":              syscall.SYS_EXIT,
	"exit_group":        syscall.SYS_EXIT_GROUP,
	"socket":            syscall.SYS_SOCKET,
	"connect":           syscall.SYS_CONNECT,
	"sendto":            syscall.SYS_SENDTO,
	"recvfrom":          syscall.SYS_RECVFROM,
	"select":            syscall.SYS_SELECT,
	"epoll_create1":     syscall.SYS_EPOLL_CREATE1,
	"epoll_ctl":         syscall.SYS_EPOLL_CTL,
	"epoll_wait":        syscall.SYS_EPOLL_WAIT,
	"getdents64":        syscall.SYS_GETDENTS64,
	"getcwd":            syscall.SYS_GETCWD,
	"getegid":           syscall.SYS_GETEGID,
	"geteuid":           syscall.SYS_GETEUID,
	"getgid":            syscall.SYS_GETGID,
	"getpid":            syscall.SYS_GETPID,
	"getppid":           syscall.SYS_GETPPID,
	"getrandom":         sysGetrandomAMD64,
	"gettid":            syscall.SYS_GETTID,
	"getuid":            syscall.SYS_GETUID,
	"lseek":             syscall.SYS_LSEEK,
	"madvise":           syscall.SYS_MADVISE,
	"nanosleep":         syscall.SYS_NANOSLEEP,
	"newfstatat":        syscall.SYS_NEWFSTATAT,
	"pipe2":             syscall.SYS_PIPE2,
	"prlimit64":         syscall.SYS_PRLIMIT64,
	"readlink":          syscall.SYS_READLINK,
	"readlinkat":        syscall.SYS_READLINKAT,
	"rt_sigaction":      syscall.SYS_RT_SIGACTION,
	"rt_sigprocmask":    syscall.SYS_RT_SIGPROCMASK,
	"rt_sigreturn":      syscall.SYS_RT_SIGRETURN,
	"sched_getaffinity": syscall.SYS_SCHED_GETAFFINITY,
	"set_robust_list":   syscall.SYS_SET_ROBUST_LIST,
	"set_tid_address":   syscall.SYS_SET_TID_ADDRESS,
	"sigaltstack":       syscall.SYS_SIGALTSTACK,
	"stat":              syscall.SYS_STAT,
	"fstat":             syscall.SYS_FSTAT,
	"lstat":             syscall.SYS_LSTAT,
	"statfs":            syscall.SYS_STATFS,
	"sysinfo":           syscall.SYS_SYSINFO,
	"uname":             syscall.SYS_UNAME,
	"dup":               syscall.SYS_DUP,
	"dup2":              syscall.SYS_DUP2,
	"dup3":              syscall.SYS_DUP3,
	"chdir":             syscall.SYS_CHDIR,
	"clock_gettime":     syscall.SYS_CLOCK_GETTIME,
	"rseq":              sysRseqAMD64,
	"mount":             syscall.SYS_MOUNT,
	"umount2":           syscall.SYS_UMOUNT2,
	"pivot_root":        syscall.SYS_PIVOT_ROOT,
	"ptrace":            syscall.SYS_PTRACE,
	"perf_event_open":   syscall.SYS_PERF_EVENT_OPEN,
	"kexec_load":        syscall.SYS_KEXEC_LOAD,
	"reboot":            syscall.SYS_REBOOT,
	"syslog":            syscall.SYS_SYSLOG,
	"setuid":            syscall.SYS_SETUID,
	"setgid":            syscall.SYS_SETGID,
	"unshare":           syscall.SYS_UNSHARE,
}

func Apply(profileID string) error {
	profile, err := policy.ResolveSeccompProfile(profileID)
	if err != nil {
		return err
	}

	filters, err := compile(profile.AllowedSyscalls)
	if err != nil {
		return err
	}
	prog := syscall.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}

	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(prSetNoNewPrivs), 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", errno)
	}
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(prSetSeccomp), uintptr(seccompModeFilter), uintptr(unsafe.Pointer(&prog)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_SECCOMP): %w", errno)
	}
	return nil
}

func compile(allowed []string) ([]syscall.SockFilter, error) {
	filters := []syscall.SockFilter{
		stmt(bpfLD|bpfW|bpfABS, seccompDataArchOffset),
		jump(bpfJMP|bpfJEQ|bpfK, auditArchAMD64, 1, 0),
		stmt(bpfRET|bpfK, seccompRetErrno|uint32(syscall.EPERM)),
		stmt(bpfLD|bpfW|bpfABS, seccompDataNR),
	}

	for _, name := range allowed {
		nr, ok := syscallNumbers[name]
		if !ok {
			return nil, fmt.Errorf("unsupported seccomp syscall %q on linux/amd64", name)
		}
		filters = append(filters, jump(bpfJMP|bpfJEQ|bpfK, nr, 0, 1))
		filters = append(filters, stmt(bpfRET|bpfK, seccompRetAllow))
	}

	filters = append(filters, stmt(bpfRET|bpfK, seccompRetErrno|uint32(syscall.EPERM)))
	return filters, nil
}

func stmt(code uint16, k uint32) syscall.SockFilter {
	return syscall.SockFilter{Code: code, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) syscall.SockFilter {
	return syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
