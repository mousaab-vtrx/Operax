package provision

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"operax/internal/policy"
	"operax/internal/spec"
)

type Provisioner interface {
	Create(context.Context, spec.WorkspaceSpec) (*spec.Workspace, error)
	Attach(context.Context, spec.WorkspaceSpec, *spec.Workspace) error
	Destroy(context.Context, *spec.Workspace) error
	Snapshot(context.Context, *spec.Workspace) (io.Reader, string, error)
	Restore(context.Context, *spec.Workspace, string) error
}

type ResourceManager interface {
	Apply(string, spec.ResourceLimits) error
	BindProcess(string, int) error
	Metrics(string) (*spec.ResourceMetrics, error)
	Remove(string) error
	Observe(string, spec.ResourceObservation) error
}

type LocalProvisioner struct {
	root string
	mu   sync.Mutex
}

func NewLocalProvisioner(root string) (*LocalProvisioner, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absRoot, 0o755); err != nil {
		return nil, err
	}
	return &LocalProvisioner{root: absRoot}, nil
}

func (p *LocalProvisioner) Create(_ context.Context, wsSpec spec.WorkspaceSpec) (*spec.Workspace, error) {
	now := time.Now().UTC()
	base := filepath.Join(p.root, wsSpec.ID)
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
	}

	for _, dir := range []string{ws.RootDir, ws.UpperDir, ws.WorkDir, ws.MergedDir, filepath.Dir(ws.TranscriptPath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	networkPlan, seccompPlan, err := policy.WritePlans(ws.RootDir, wsSpec)
	if err != nil {
		return nil, err
	}
	ws.NetworkPlan = networkPlan
	ws.SeccompPlan = seccompPlan
	if wsSpec.RestoreSnapshot != "" {
		if err := p.Restore(context.Background(), ws, wsSpec.RestoreSnapshot); err != nil {
			return nil, err
		}
	}
	return ws, nil
}

func (p *LocalProvisioner) Attach(ctx context.Context, wsSpec spec.WorkspaceSpec, ws *spec.Workspace) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	transcript, err := os.OpenFile(ws.TranscriptPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = transcript.Sync()
		_ = transcript.Close()
	}()

	command := interactiveCommand(wsSpec.Command)
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = ws.MergedDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, transcript)
	cmd.Env = append(os.Environ(),
		"OPERAX_WORKSPACE_ID="+ws.ID,
		"OPERAX_TENANT_ID="+ws.TenantID,
		"OPERAX_NETWORK_POLICY="+string(wsSpec.NetworkPolicy),
		"OPERAX_SECCOMP_PROFILE="+wsSpec.SeccompProfileID,
	)
	cmd.Env = append(cmd.Env, interactiveEnv()...)

	if _, err := fmt.Fprintf(transcript, "[%s] attach command=%q\n", time.Now().UTC().Format(time.RFC3339), command); err != nil {
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
		_, _ = fmt.Fprintf(transcript, "[%s] attach failed: %v\n", time.Now().UTC().Format(time.RFC3339), runErr)
	}

	violations := policy.EvaluateCommand(wsSpec, cmdProcessStatePid(cmd))
	if len(violations) > 0 {
		for _, violation := range violations {
			if _, err := fmt.Fprintf(
				transcript,
				"[%s] seccomp_violation syscall=%s result=%s pid=%d\n",
				time.Now().UTC().Format(time.RFC3339),
				violation.Syscall,
				violation.Result,
				violation.PID,
			); err != nil {
				return err
			}
		}
	}
	return runErr
}

func (p *LocalProvisioner) Destroy(_ context.Context, ws *spec.Workspace) error {
	return os.RemoveAll(ws.RootDir)
}

func (p *LocalProvisioner) Snapshot(_ context.Context, ws *spec.Workspace) (io.Reader, string, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.Walk(ws.MergedDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == ws.MergedDir {
			return nil
		}

		rel, err := filepath.Rel(ws.MergedDir, path)
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

func (p *LocalProvisioner) Restore(_ context.Context, ws *spec.Workspace, snapshotPath string) error {
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
		target := filepath.Join(ws.MergedDir, header.Name)
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

type StaticResourceManager struct {
	mu      sync.RWMutex
	limits  map[string]spec.ResourceLimits
	metrics map[string]spec.ResourceMetrics
	heat    map[string]int
}

func NewStaticResourceManager() *StaticResourceManager {
	return &StaticResourceManager{
		limits:  make(map[string]spec.ResourceLimits),
		metrics: make(map[string]spec.ResourceMetrics),
		heat:    make(map[string]int),
	}
}

func (m *StaticResourceManager) Apply(id string, limits spec.ResourceLimits) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.limits[id] = limits
	m.metrics[id] = spec.ResourceMetrics{
		CPUQuotaMicros: limits.CPUQuota,
		LastUpdated:    time.Now().UTC(),
		EnforcementNotes: []string{
			"resource metrics are process-observed in the local provisioner; cgroup v2 enforcement hooks are the next implementation step",
		},
	}
	return nil
}

func (m *StaticResourceManager) Metrics(id string) (*spec.ResourceMetrics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics, ok := m.metrics[id]
	if !ok {
		return nil, fmt.Errorf("metrics not found for workspace %s", id)
	}
	copy := metrics
	return &copy, nil
}

func (m *StaticResourceManager) BindProcess(string, int) error {
	return nil
}

func (m *StaticResourceManager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.limits, id)
	delete(m.metrics, id)
	delete(m.heat, id)
	return nil
}

func (m *StaticResourceManager) Observe(id string, obs spec.ResourceObservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics, ok := m.metrics[id]
	if !ok {
		return fmt.Errorf("metrics not found for workspace %s", id)
	}
	if obs.MemoryCurrent > metrics.MemoryPeak {
		metrics.MemoryPeak = obs.MemoryCurrent
	}
	if obs.PidsCurrent > metrics.PidsPeak {
		metrics.PidsPeak = obs.PidsCurrent
	}
	metrics.MemoryCurrent = obs.MemoryCurrent
	metrics.IOReadBytes += obs.IOReadBytesDelta
	metrics.IOWriteBytes += obs.IOWriteBytesDelta
	metrics.PidsCurrent = obs.PidsCurrent
	m.applyThermalThrottling(id, &metrics, obs)
	metrics.LastUpdated = time.Now().UTC()
	m.metrics[id] = metrics
	return nil
}

func (m *StaticResourceManager) applyThermalThrottling(id string, metrics *spec.ResourceMetrics, obs spec.ResourceObservation) {
	limits, ok := m.limits[id]
	if !ok || limits.CPUQuota <= 0 {
		return
	}
	memRatio := ratio(obs.MemoryCurrent, limits.MemLimitBytes)
	pidRatio := ratio(obs.PidsCurrent, limits.PidsMax)
	heatScore := (0.7 * memRatio) + (0.3 * pidRatio)
	metrics.ThermalScore = heatScore
	metrics.ThermalState = thermalState(heatScore)
	metrics.ThermalThrottled = false
	if heatScore > 0.85 {
		m.heat[id]++
	} else {
		m.heat[id] = 0
		metrics.CPUQuotaMicros = limits.CPUQuota
		return
	}
	if m.heat[id] >= 3 {
		throttled := int64(float64(limits.CPUQuota) * 0.8)
		if throttled < 10_000 {
			throttled = 10_000
		}
		metrics.ThermalThrottled = true
		metrics.CPUQuotaMicros = throttled
		metrics.EnforcementNotes = append(metrics.EnforcementNotes,
			fmt.Sprintf("thermal throttling active: heat=%.2f cpu_quota=%d->%d", heatScore, limits.CPUQuota, throttled),
		)
		return
	}
	metrics.CPUQuotaMicros = limits.CPUQuota
}

func ratio(current, limit int64) float64 {
	if limit <= 0 {
		return 0
	}
	r := float64(current) / float64(limit)
	if r < 0 {
		return 0
	}
	if r > 1 {
		return 1
	}
	return r
}

func thermalState(score float64) string {
	switch {
	case score >= 0.85:
		return "critical"
	case score >= 0.70:
		return "hot"
	case score >= 0.40:
		return "warm"
	default:
		return "cool"
	}
}

func cmdProcessStatePid(cmd *exec.Cmd) int {
	if cmd == nil || cmd.Process == nil {
		return 0
	}
	return cmd.Process.Pid
}
