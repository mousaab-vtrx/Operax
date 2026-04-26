//go:build linux

package kernelrun

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"operax/internal/seccomp"
)

func Dispatch(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "internal-kernel-init":
		return true, runInit(args[1:])
	case "internal-kernel-exec":
		return true, runExec(args[1:])
	default:
		return false, nil
	}
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("internal-kernel-init", flag.ContinueOnError)
	hostname := fs.String("hostname", "operax", "workspace hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := syscall.Sethostname([]byte(*hostname)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	if err := syscall.Mount("", "/", "", uintptr(syscall.MS_REC|syscall.MS_PRIVATE), ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	return nil
}

func runExec(args []string) error {
	fs := flag.NewFlagSet("internal-kernel-exec", flag.ContinueOnError)
	root := fs.String("root", "", "overlay root")
	profile := fs.String("profile", "", "seccomp profile")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if *root == "" {
		return errors.New("missing --root")
	}
	if *profile == "" {
		return errors.New("missing --profile")
	}
	if len(command) == 0 {
		return errors.New("missing command")
	}

	if err := os.Chdir(*root); err != nil {
		return fmt.Errorf("chdir root: %w", err)
	}
	if err := syscall.Chroot(*root); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	if err := ensureProcMounted(); err != nil {
		return err
	}
	if err := seccomp.Apply(*profile); err != nil {
		return err
	}
	return syscall.Exec(command[0], command, os.Environ())
}

func ensureProcMounted() error {
	if err := os.MkdirAll("/proc", 0o755); err != nil {
		return err
	}
	if _, err := os.Stat("/proc/1"); err == nil {
		return nil
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil && !errors.Is(err, syscall.EBUSY) {
		return fmt.Errorf("mount proc: %w", err)
	}
	return nil
}

func Executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}
