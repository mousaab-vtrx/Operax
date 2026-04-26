//go:build linux

package provision

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"operax/internal/policy"
	"operax/internal/spec"
)

type KernelProvisioner struct {
	root            string
	helperPath      string
	defaultLowerDir string
}

func NewKernelProvisioner(root, helperPath, defaultLowerDir string) (*KernelProvisioner, error) {
	if helperPath == "" {
		return nil, fmt.Errorf("helper path is required for kernel provisioner")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absRoot, 0o755); err != nil {
		return nil, err
	}
	return &KernelProvisioner{root: absRoot, helperPath: helperPath, defaultLowerDir: defaultLowerDir}, nil
}

func KernelBackendAvailable() bool {
	if runtimeGOOS() != "linux" {
		return false
	}
	for _, cmd := range []string{"unshare", "nsenter", "ip", "nft", "mount", "umount"} {
		if _, err := exec.LookPath(cmd); err != nil {
			return false
		}
	}
	return os.Geteuid() == 0
}

func (p *KernelProvisioner) Create(ctx context.Context, wsSpec spec.WorkspaceSpec) (*spec.Workspace, error) {
	lowerDir := wsSpec.LowerDir
	if lowerDir == "" {
		lowerDir = p.defaultLowerDir
	}
	if lowerDir == "" {
		return nil, fmt.Errorf("kernel backend requires a lowerdir; set --lowerdir or OPERAX_LOWERDIR")
	}
	if _, err := os.Stat(lowerDir); err != nil {
		return nil, fmt.Errorf("lowerdir %q: %w", lowerDir, err)
	}

	now := time.Now().UTC()
	base := filepath.Join(p.root, wsSpec.ID)
	if err := p.cleanupStaleWorkspace(ctx, wsSpec.ID, base); err != nil {
		return nil, err
	}
	ws := &spec.Workspace{
		ID:             wsSpec.ID,
		TenantID:       wsSpec.TenantID,
		State:          spec.StateReady,
		CreatedAt:      now,
		UpdatedAt:      now,
		ExpiresAt:      now.Add(wsSpec.TTL),
		RootDir:        base,
		UpperDir:       filepath.Join(base, "upper"),
		WorkDir:        filepath.Join(base, "work"),
		MergedDir:      filepath.Join(base, "merged"),
		TranscriptPath: filepath.Join(base, "audit", "transcript.log"),
		AuditPath:      filepath.Join(base, "audit", "record.json"),
		Backend:        "kernel",
	}
	for _, dir := range []string{ws.RootDir, ws.UpperDir, ws.WorkDir, ws.MergedDir, filepath.Join(ws.RootDir, "audit")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if wsSpec.RestoreSnapshot != "" {
		if err := p.Restore(ctx, ws, wsSpec.RestoreSnapshot); err != nil {
			return nil, err
		}
	}
	networkPlan, seccompPlan, err := policy.WritePlans(ws.RootDir, wsSpec)
	if err != nil {
		return nil, err
	}
	ws.NetworkPlan = networkPlan
	ws.SeccompPlan = seccompPlan

	initCmd := exec.CommandContext(ctx, p.helperPath, "internal-kernel-init", "--hostname", ws.ID)
	initLog, err := os.OpenFile(filepath.Join(ws.RootDir, "audit", "init.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	initCmd.Stdout = initLog
	initCmd.Stderr = initLog
	initCmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER | syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getegid(), Size: 1},
		},
	}
	if err := initCmd.Start(); err != nil {
		_ = initLog.Close()
		return nil, err
	}
	_ = initLog.Close()

	ws.InitPID = initCmd.Process.Pid
	if err := os.WriteFile(filepath.Join(ws.RootDir, "init.pid"), []byte(strconv.Itoa(ws.InitPID)), 0o644); err != nil {
		_ = p.Destroy(ctx, ws)
		return nil, err
	}
	if err := p.mountOverlay(ctx, ws, lowerDir); err != nil {
		_ = p.Destroy(ctx, ws)
		return nil, err
	}
	if err := p.configureNetwork(ctx, ws, wsSpec); err != nil {
		_ = p.Destroy(ctx, ws)
		return nil, err
	}
	return ws, nil
}

func (p *KernelProvisioner) Attach(ctx context.Context, wsSpec spec.WorkspaceSpec, ws *spec.Workspace) error {
	transcript, err := os.OpenFile(ws.TranscriptPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = transcript.Sync()
		_ = transcript.Close()
	}()

	command := interactiveCommand(wsSpec.Command)
	args := []string{
		"-t", strconv.Itoa(ws.InitPID),
		"-p", "-n", "-m", "-u", "-U",
		"--", p.helperPath, "internal-kernel-exec",
		"--root", ws.MergedDir,
		"--profile", wsSpec.SeccompProfileID,
	}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, transcript)
	cmd.Env = append(os.Environ(),
		"OPERAX_BACKEND=kernel",
		"OPERAX_WORKSPACE_ID="+ws.ID,
		"OPERAX_TENANT_ID="+ws.TenantID,
		"OPERAX_NETWORK_POLICY="+string(wsSpec.NetworkPolicy),
	)
	cmd.Env = append(cmd.Env, interactiveEnv()...)
	if _, err := fmt.Fprintf(transcript, "[%s] kernel attach command=%q pid=%d\n", time.Now().UTC().Format(time.RFC3339), command, ws.InitPID); err != nil {
		return err
	}

	// Set up signal handling for clean interrupt
	sigChan := make(chan os.Signal, 1)
	go func() {
		sig := <-sigChan
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
		_, _ = fmt.Fprintf(transcript, "[%s] interrupted by signal %v\n", time.Now().UTC().Format(time.RFC3339), sig)
	}()

	runErr := cmd.Run()
	if runErr != nil {
		_, _ = fmt.Fprintf(transcript, "[%s] kernel attach failed: %v\n", time.Now().UTC().Format(time.RFC3339), runErr)
	}
	return runErr
}

func (p *KernelProvisioner) Destroy(ctx context.Context, ws *spec.Workspace) error {
	if ws.InitPID > 0 {
		_ = p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-m", "--", "umount", "-l", filepath.Join(ws.MergedDir, "proc"))
		_ = p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-m", "--", "umount", "-l", ws.MergedDir)
	}
	if ws.NFTTable != "" {
		_ = p.run(ctx, "nft", "delete", "table", "inet", ws.NFTTable)
	}
	if ws.NFTNatTable != "" {
		_ = p.run(ctx, "nft", "delete", "table", "ip", ws.NFTNatTable)
	}
	if ws.HostVeth != "" {
		_ = p.run(ctx, "ip", "link", "del", ws.HostVeth)
	}
	if ws.InitPID > 0 {
		if proc, err := os.FindProcess(ws.InitPID); err == nil {
			_ = proc.Signal(syscall.SIGTERM)
		}
	}
	return os.RemoveAll(ws.RootDir)
}

func (p *KernelProvisioner) cleanupStaleWorkspace(ctx context.Context, workspaceID, base string) error {
	hostVeth := "ws-" + shortID(workspaceID) + "-h"
	table := "operax_" + sanitizeID(workspaceID)
	natTable := table + "_nat"

	if data, err := os.ReadFile(filepath.Join(base, "init.pid")); err == nil {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil && pid > 0 {
			if proc, findErr := os.FindProcess(pid); findErr == nil {
				_ = proc.Signal(syscall.SIGTERM)
				time.Sleep(150 * time.Millisecond)
			}
		}
	}

	_ = p.run(ctx, "nft", "delete", "table", "inet", table)
	_ = p.run(ctx, "nft", "delete", "table", "ip", natTable)
	_ = p.run(ctx, "ip", "link", "del", hostVeth)
	_ = os.RemoveAll(base)
	return nil
}

func (p *KernelProvisioner) Snapshot(_ context.Context, ws *spec.Workspace) (io.Reader, string, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.Walk(ws.UpperDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == ws.UpperDir {
			return nil
		}
		rel, err := filepath.Rel(ws.UpperDir, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = tw.Close()
		return nil, "", err
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}

	snapshotPath := filepath.Join(ws.RootDir, "snapshots", time.Now().UTC().Format("20060102T150405Z")+".tar")
	if err := os.MkdirAll(filepath.Dir(snapshotPath), 0o755); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(snapshotPath, buf.Bytes(), 0o644); err != nil {
		return nil, "", err
	}
	return bytes.NewReader(buf.Bytes()), snapshotPath, nil
}

func (p *KernelProvisioner) Restore(_ context.Context, ws *spec.Workspace, snapshotPath string) error {
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(ws.UpperDir, header.Name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			content, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, content, os.FileMode(header.Mode)); err != nil {
				return err
			}
		}
	}
}

func (p *KernelProvisioner) mountOverlay(ctx context.Context, ws *spec.Workspace, lowerDir string) error {
	if err := os.MkdirAll(filepath.Join(ws.MergedDir, "proc"), 0o755); err != nil {
		return err
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerDir, ws.UpperDir, ws.WorkDir)
	if err := p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-m", "--", "mount", "-t", "overlay", "overlay", "-o", opts, ws.MergedDir); err != nil {
		return err
	}
	return p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-m", "--", "mount", "-t", "proc", "proc", filepath.Join(ws.MergedDir, "proc"))
}

func (p *KernelProvisioner) configureNetwork(ctx context.Context, ws *spec.Workspace, wsSpec spec.WorkspaceSpec) error {
	hostVeth := "ws-" + shortID(ws.ID) + "-h"
	peerName := "ws-" + shortID(ws.ID) + "-g"
	table := "operax_" + sanitizeID(ws.ID)
	natTable := table + "_nat"

	hostCIDR, guestCIDR, hostIP, subnet := addressPlan(ws.ID)
	ws.HostVeth = hostVeth
	ws.GuestVeth = "eth0"
	ws.NFTTable = table
	ws.NFTNatTable = natTable
	ws.HostAddress = hostCIDR
	ws.GuestAddress = guestCIDR

	if err := p.run(ctx, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", peerName); err != nil {
		return err
	}
	if err := p.run(ctx, "ip", "link", "set", peerName, "netns", strconv.Itoa(ws.InitPID)); err != nil {
		return err
	}
	if err := p.run(ctx, "ip", "addr", "add", hostCIDR, "dev", hostVeth); err != nil {
		return err
	}
	if err := p.run(ctx, "ip", "link", "set", hostVeth, "up"); err != nil {
		return err
	}
	if err := p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-n", "--", "ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-n", "--", "ip", "link", "set", peerName, "name", "eth0"); err != nil {
		return err
	}
	if err := p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-n", "--", "ip", "addr", "add", guestCIDR, "dev", "eth0"); err != nil {
		return err
	}
	if err := p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-n", "--", "ip", "link", "set", "eth0", "up"); err != nil {
		return err
	}
	if err := p.run(ctx, "nsenter", "-t", strconv.Itoa(ws.InitPID), "-n", "--", "ip", "route", "add", "default", "via", hostIP); err != nil {
		return err
	}

	defaultIF, err := defaultRouteInterface(ctx)
	if err != nil {
		return err
	}
	filterScript := buildFilterTable(table, hostVeth, wsSpec)
	if err := p.runWithInput(ctx, filterScript, "nft", "-f", "-"); err != nil {
		return err
	}
	if wsSpec.NetworkPolicy != spec.NetworkNone {
		natScript := buildNATTable(natTable, subnet, defaultIF)
		if err := p.runWithInput(ctx, natScript, "nft", "-f", "-"); err != nil {
			return err
		}
	}
	return nil
}

func (p *KernelProvisioner) run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *KernelProvisioner) runWithInput(ctx context.Context, input string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

type KernelResourceManager struct {
	root  string
	paths map[string]string
}

func NewKernelResourceManager(root string) (*KernelResourceManager, error) {
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	base := filepath.Join(root, "operax")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, err
	}
	_ = os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+cpu +memory +io +pids"), 0o644)
	_ = os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+cpu +memory +io +pids"), 0o644)
	return &KernelResourceManager{root: root, paths: map[string]string{}}, nil
}

func (m *KernelResourceManager) Apply(id string, limits spec.ResourceLimits) error {
	path := m.pathFor(id)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("failed to create cgroup directory: %w", err)
	}

	// Apply CPU limits (cpu.max in cgroup v2: quota period format)
	cpuSpec := fmt.Sprintf("%d %d", limits.CPUQuota, limits.CPUPeriod)
	if err := os.WriteFile(filepath.Join(path, "cpu.max"), []byte(cpuSpec), 0o644); err != nil {
		return fmt.Errorf("failed to set cpu.max to %q: %w", cpuSpec, err)
	}

	// Apply memory limits
	memSpec := strconv.FormatInt(limits.MemLimitBytes, 10)
	if err := os.WriteFile(filepath.Join(path, "memory.max"), []byte(memSpec), 0o644); err != nil {
		return fmt.Errorf("failed to set memory.max to %d bytes: %w", limits.MemLimitBytes, err)
	}

	// Disable swap (memory.swap.max = 0)
	if err := os.WriteFile(filepath.Join(path, "memory.swap.max"), []byte("0"), 0o644); err != nil {
		// Non-fatal: some kernel configs don't support swap limiting
		_ = fmt.Errorf("warning: failed to disable swap: %w", err)
	}

	// Apply PID limits
	if limits.PidsMax > 0 {
		pidsSpec := strconv.FormatInt(limits.PidsMax, 10)
		if err := os.WriteFile(filepath.Join(path, "pids.max"), []byte(pidsSpec), 0o644); err != nil {
			return fmt.Errorf("failed to set pids.max to %d: %w", limits.PidsMax, err)
		}
	}

	// Apply I/O bandwidth limits (io.max in cgroup v2)
	// Format: major:minor rbps=X wbps=Y
	if limits.IOReadBps > 0 || limits.IOWriteBps > 0 {
		if stat, err := os.Stat("/"); err == nil {
			if st, ok := stat.Sys().(*syscall.Stat_t); ok {
				major, minor := majorMinor(st.Dev)
				var parts []string
				if limits.IOReadBps > 0 {
					parts = append(parts, "rbps="+strconv.FormatInt(limits.IOReadBps, 10))
				}
				if limits.IOWriteBps > 0 {
					parts = append(parts, "wbps="+strconv.FormatInt(limits.IOWriteBps, 10))
				}
				if len(parts) > 0 {
					ioSpec := fmt.Sprintf("%d:%d %s", major, minor, strings.Join(parts, " "))
					if err := os.WriteFile(filepath.Join(path, "io.max"), []byte(ioSpec), 0o644); err != nil {
						// Non-fatal: some filesystems don't support I/O limits
						_ = fmt.Errorf("warning: failed to set io.max: %w", err)
					}
				}
			}
		}
	}

	m.paths[id] = path
	return nil
}

func (m *KernelResourceManager) BindProcess(id string, pid int) error {
	path := m.pathFor(id)
	cgroupProcPath := filepath.Join(path, "cgroup.procs")
	pidStr := strconv.Itoa(pid)

	if err := os.WriteFile(cgroupProcPath, []byte(pidStr), 0o644); err != nil {
		return fmt.Errorf("failed to bind process %d to workspace %s: %w", pid, id, err)
	}
	return nil
}

func (m *KernelResourceManager) Metrics(id string) (*spec.ResourceMetrics, error) {
	path := m.pathFor(id)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("cgroup path not found for %s", id)
	}
	metrics := &spec.ResourceMetrics{LastUpdated: time.Now().UTC()}
	if value, err := readIntFile(filepath.Join(path, "memory.current")); err == nil {
		metrics.MemoryCurrent = value
	}
	if value, err := readIntFile(filepath.Join(path, "memory.peak")); err == nil {
		metrics.MemoryPeak = value
	}
	if value, err := readIntFile(filepath.Join(path, "pids.current")); err == nil {
		metrics.PidsCurrent = value
	}
	if value, err := readIntFile(filepath.Join(path, "pids.peak")); err == nil {
		metrics.PidsPeak = value
	}
	if usage, err := readCPUUsage(filepath.Join(path, "cpu.stat")); err == nil {
		metrics.CPUQuotaMicros = usage
	}
	if r, w, err := readIOStat(filepath.Join(path, "io.stat")); err == nil {
		metrics.IOReadBytes = r
		metrics.IOWriteBytes = w
	}
	metrics.EnforcementNotes = []string{"metrics sourced from cgroup v2 control files"}
	return metrics, nil
}

func (m *KernelResourceManager) Remove(id string) error {
	path := m.pathFor(id)
	delete(m.paths, id)
	return os.RemoveAll(path)
}

func (m *KernelResourceManager) Observe(string, spec.ResourceObservation) error {
	return nil
}

func (m *KernelResourceManager) pathFor(id string) string {
	if path, ok := m.paths[id]; ok {
		return path
	}
	path := filepath.Join(m.root, "operax", id)
	m.paths[id] = path
	return path
}

func buildFilterTable(table, iface string, wsSpec spec.WorkspaceSpec) string {
	var rules []string
	rules = append(rules, fmt.Sprintf("    ct state established,related accept"))
	switch wsSpec.NetworkPolicy {
	case spec.NetworkNone:
		rules = append(rules, fmt.Sprintf("    iifname %q drop", iface))
	case spec.NetworkAllowlist:
		rules = append(rules, fmt.Sprintf("    iifname %q ip daddr { %s } accept", iface, strings.Join(wsSpec.AllowedCIDRs, ", ")))
		rules = append(rules, fmt.Sprintf("    iifname %q drop", iface))
	default:
		rules = append(rules, fmt.Sprintf("    iifname %q accept", iface))
	}
	return fmt.Sprintf("add table inet %s\nadd chain inet %s forward { type filter hook forward priority 0; policy accept; }\nadd rule inet %s forward %s\n", table, table, table, strings.Join(rules, "\nadd rule inet "+table+" forward "))
}

func buildNATTable(table, subnet, defaultIF string) string {
	return fmt.Sprintf("add table ip %s\nadd chain ip %s postrouting { type nat hook postrouting priority 100; policy accept; }\nadd rule ip %s postrouting oifname %q ip saddr %s masquerade\n", table, table, table, defaultIF, subnet)
}

func defaultRouteInterface(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("default route interface not found")
}

func addressPlan(id string) (hostCIDR, guestCIDR, hostIP, subnet string) {
	sum := sha1.Sum([]byte(id))
	third := 200 + int(sum[0]%40)
	base := int(sum[1]%63) * 4
	if base == 0 {
		base = 4
	}
	hostIP = fmt.Sprintf("10.%d.%d.%d", 240, third, base+1)
	guestIP := fmt.Sprintf("10.%d.%d.%d", 240, third, base+2)
	subnet = fmt.Sprintf("10.%d.%d.%d/30", 240, third, base)
	hostCIDR = hostIP + "/30"
	guestCIDR = guestIP + "/30"
	return hostCIDR, guestCIDR, hostIP, subnet
}

func shortID(id string) string {
	id = sanitizeID(id)
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func sanitizeID(id string) string {
	id = strings.ToLower(id)
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}

func readIntFile(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func readCPUUsage(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "usage_usec" {
			return strconv.ParseInt(fields[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("usage_usec not found")
}

func readIOStat(path string) (int64, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return 0, 0, nil
	}
	var readBytes, writeBytes int64
	for _, line := range strings.Split(trimmed, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "rbytes=") {
				v, _ := strconv.ParseInt(strings.TrimPrefix(field, "rbytes="), 10, 64)
				readBytes += v
			}
			if strings.HasPrefix(field, "wbytes=") {
				v, _ := strconv.ParseInt(strings.TrimPrefix(field, "wbytes="), 10, 64)
				writeBytes += v
			}
		}
	}
	return readBytes, writeBytes, nil
}

func majorMinor(dev uint64) (uint64, uint64) {
	return (dev >> 8) & 0xfff, (dev & 0xff) | ((dev >> 12) & 0xfff00)
}

func runtimeGOOS() string {
	return "linux"
}
