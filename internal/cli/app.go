package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"operax/internal/audit"
	apperrors "operax/internal/errors"
	"operax/internal/kernelrun"
	"operax/internal/logging"
	"operax/internal/metrics"
	"operax/internal/orchestrator"
	"operax/internal/pagination"
	"operax/internal/policy"
	"operax/internal/provision"
	"operax/internal/spec"
	"operax/internal/store"
)

type App struct {
	orch      *orchestrator.Orchestrator
	metrics   *metrics.Metrics
	auditSink audit.Sink
	logger    *slog.Logger
}

func NewApp(dataRoot string) (*App, error) {
	absDataRoot, err := filepath.Abs(dataRoot)
	if err != nil {
		return nil, err
	}

	stateStore, err := store.NewFileStore(filepath.Join(absDataRoot, "state"))
	if err != nil {
		return nil, err
	}
	sink, err := audit.NewFileSink(filepath.Join(absDataRoot, "audit"))
	if err != nil {
		return nil, err
	}
	helperPath, err := kernelrun.Executable()
	if err != nil {
		return nil, err
	}
	prov, res, err := selectBackend(filepath.Join(absDataRoot, "workspaces"), helperPath)
	if err != nil {
		return nil, err
	}
	orch := orchestrator.New(prov, res, stateStore, sink, time.Second)
	if err := orch.Recover(ctxWithLogger(context.Background())); err != nil {
		return nil, err
	}
	return &App{
		orch:      orch,
		metrics:   metrics.New(),
		auditSink: sink,
		logger:    logging.GetLogger(),
	}, nil
}

func (a *App) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return a.usage()
	}

	switch args[0] {
	case "create":
		return a.create(ctx, args[1:])
	case "create-agent":
		return a.createAgent(ctx, args[1:])
	case "attach":
		return a.attach(ctx, args[1:])
	case "destroy":
		return a.destroy(ctx, args[1:])
	case "list":
		return a.list(ctx, args[1:])
	case "get":
		return a.get(ctx, args[1:])
	case "metrics":
		return a.showMetrics(ctx, args[1:])
	case "audit":
		return a.audit(ctx, args[1:])
	case "snapshot":
		return a.snapshot(ctx, args[1:])
	case "restore":
		return a.restore(ctx, args[1:])
	case "suspend":
		return a.suspend(ctx, args[1:])
	case "reap":
		return a.reap(ctx, args[1:])
	case "explain-policy":
		return a.explainPolicy(args[1:])
	default:
		return a.usage()
	}
}

func (a *App) usage() error {
	fmt.Fprintf(os.Stderr, "operax commands: create attach destroy list get metrics audit snapshot restore suspend reap create-agent explain-policy\n")
	return fmt.Errorf("missing or unknown command")
}

func (a *App) create(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	ttl := fs.Duration("ttl", 60*time.Second, "workspace time to live")
	cpuPercent := fs.Int64("cpu", 20, "cpu percentage of one core")
	memMB := fs.Int64("mem", 512, "memory limit in MiB")
	netPolicy := fs.String("net", "none", "network policy: none, allowlist, open")
	allowCIDRs := fs.String("allow-cidrs", "", "comma-separated allowlist CIDRs")
	profile := fs.String("profile", "default", "seccomp profile id")
	tenant := fs.String("tenant", "default", "tenant identifier")
	command := fs.String("command", "/bin/sh", "command to run on attach")
	lowerDir := fs.String("lowerdir", os.Getenv("OPERAX_LOWERDIR"), "read-only lowerdir for kernel backend")
	snapshotOnExit := fs.Bool("snapshot-on-exit", false, "snapshot before destroy")
	id := fs.String("id", "", "workspace identifier")
	restoreSnapshot := fs.String("restore", "", "restore workspace contents from snapshot tar")
	aiMode := fs.Bool("ai-mode", false, "enable AI agent defaults (4GB mem, network allowlist, extended TTL)")
	dryRun := fs.Bool("dry-run", false, "print resulting workspace spec and policy plan without creating")
	if err := fs.Parse(args); err != nil {
		a.logger.Error("create parse failed", "err", err)
		return err
	}

	if *aiMode {
		applyAIModeDefaults(fs, ttl, cpuPercent, memMB, netPolicy, allowCIDRs)
	}

	workspaceID := *id
	if workspaceID == "" {
		workspaceID = "ws-" + randomID(4)
	}

	wsSpec := buildWorkspaceSpec(workspaceSpecInput{
		id:              workspaceID,
		tenant:          *tenant,
		ttl:             *ttl,
		cpuPercent:      *cpuPercent,
		memMB:           *memMB,
		netPolicy:       *netPolicy,
		allowCIDRs:      *allowCIDRs,
		profile:         *profile,
		lowerDir:        *lowerDir,
		command:         *command,
		snapshotOnExit:  *snapshotOnExit,
		restoreSnapshot: *restoreSnapshot,
		pidsMax:         256,
	})
	if *dryRun {
		return printDryRun(wsSpec)
	}

	a.logger.Info("creating workspace", "id", workspaceID, "tenant", *tenant, "ttl", ttl)
	rec, err := a.orch.CreateWorkspace(ctx, wsSpec)
	if err != nil {
		a.logger.Error("create workspace failed", "id", workspaceID, "err", err)
		a.metrics.RecordWorkspaceFailed()
		return userFacingError(err)
	}
	a.metrics.RecordWorkspaceCreated()
	a.metrics.RecordWorkspaceStateTransition(string(rec.Workspace.State))
	fmt.Printf("Workspace created: %s\n", rec.Workspace.ID)
	fmt.Println(spec.Pretty(rec))
	a.logger.Info("workspace created successfully", "id", workspaceID)
	return nil
}

func (a *App) attach(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: operax attach <workspace-id>")
	}

	wsID := args[0]

	a.logger.Info("attaching to workspace", "id", wsID)
	if err := a.orch.AttachWorkspace(ctx, wsID); err != nil {
		a.logger.Error("attach failed", "id", wsID, "err", err)
		return userFacingError(err)
	}
	a.logger.Info("workspace attached successfully", "id", wsID)
	return nil
}

func (a *App) destroy(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: operax destroy <workspace-id>")
	}

	wsID := args[0]

	a.logger.Info("destroying workspace", "id", wsID)
	if err := a.orch.DestroyWorkspace(ctx, wsID, "cli", "destroy requested by operator"); err != nil {
		a.logger.Error("destroy failed", "id", wsID, "err", err)
		return userFacingError(err)
	}
	a.logger.Info("workspace destroyed successfully", "id", wsID)
	return nil
}

func (a *App) list(ctx context.Context, args []string) error {
	a.logger.Info("listing workspaces")
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	offset := fs.Int("offset", 0, "pagination offset")
	limit := fs.Int("limit", 50, "pagination limit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Use paginated API if available
	page := pagination.NewPageInfo(*offset, *limit)
	result, err := a.orch.ListPaginated(ctx, page)
	if err != nil {
		a.logger.Error("list failed", "err", err)
		return userFacingError(err)
	}

	a.logger.Info("workspaces retrieved", "count", len(result.Items), "total", result.Total, "offset", result.Offset, "limit", result.Limit)

	// Display pagination info
	if result.Total > 0 {
		fmt.Printf("Showing %d of %d workspaces (offset: %d, limit: %d)\n", len(result.Items), result.Total, result.Offset, result.Limit)
		if result.HasPrev {
			fmt.Printf("  Previous page: --offset %d\n", result.PrevOffset)
		}
		if result.HasNext {
			fmt.Printf("  Next page: --offset %d\n", result.NextOffset)
		}
		fmt.Println()
	}

	// Display workspaces
	for _, rec := range result.Items {
		status := string(rec.Workspace.State)
		if rec.Workspace.State != spec.StateDestroyed && rec.Workspace.IsExpired() {
			status = string(spec.StateDestroyed) + "|EXPIRED"
		} else if rec.Workspace.State != spec.StateDestroyed && rec.Workspace.IsExpiringSoon(10*time.Second) {
			remaining := rec.Workspace.TimeRemaining()
			status = string(rec.Workspace.State) + fmt.Sprintf("|EXPIRING_SOON(%s)", fmtDuration(remaining))
		}
		fmt.Printf("%s\t%s\t%s\t%s (expires in %s)\n",
			rec.Workspace.ID, status, rec.Spec.TenantID,
			rec.Workspace.ExpiresAt.Format(time.RFC3339),
			fmtDuration(rec.Workspace.TimeRemaining()))
	}
	return nil
}

func (a *App) get(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: operax get <workspace-id>")
	}
	rec, err := a.orch.Get(ctx, args[0])
	if err != nil {
		a.logger.Error("get workspace failed", "id", args[0], "err", err)
		return userFacingError(err)
	}
	fmt.Println(spec.Pretty(rec))
	return nil
}

func (a *App) showMetrics(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: operax metrics <workspace-id>")
	}
	metrics, err := a.orch.Metrics(ctx, args[0])
	if err != nil {
		a.logger.Error("get metrics failed", "id", args[0], "err", err)
		return userFacingError(err)
	}
	fmt.Println(spec.Pretty(metrics))
	if metrics.ThermalState != "" {
		fmt.Printf("Thermal state: %s (score %.2f, throttled=%t)\n", metrics.ThermalState, metrics.ThermalScore, metrics.ThermalThrottled)
	}
	return nil
}

func (a *App) audit(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: operax audit <workspace-id>")
	}
	record, err := a.orch.Audit(ctx, args[0])
	if err != nil {
		a.logger.Error("get audit failed", "id", args[0], "err", err)
		return userFacingError(err)
	}
	fmt.Println(spec.Pretty(record))
	return nil
}

func (a *App) snapshot(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: operax snapshot <workspace-id>")
	}
	wsID := args[0]

	a.logger.Info("creating snapshot", "id", wsID)
	path, err := a.orch.SnapshotWorkspace(ctx, wsID)
	if err != nil {
		a.logger.Error("snapshot failed", "id", wsID, "err", err)
		a.metrics.RecordSnapshotFailed()
		return userFacingError(err)
	}
	a.metrics.RecordSnapshotCreated()
	fmt.Printf("Snapshot stored at %s\n", path)
	a.logger.Info("snapshot created successfully", "id", wsID, "path", path)
	return nil
}

func (a *App) restore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	snapshotPath := fs.String("snapshot", "", "path to snapshot tar")
	id := fs.String("id", "", "workspace identifier")
	tenant := fs.String("tenant", "default", "tenant identifier")
	netPolicy := fs.String("net", "allowlist", "network policy: none, allowlist, open")
	allowCIDRs := fs.String("allow-cidrs", "10.0.0.0/8", "comma-separated allowlist CIDRs")
	profile := fs.String("profile", "default", "seccomp profile id")
	command := fs.String("command", "/bin/sh", "command to run on attach")
	ttl := fs.Duration("ttl", 5*time.Minute, "workspace time to live")
	memMB := fs.Int64("mem", 512, "memory limit in MiB")
	cpuPercent := fs.Int64("cpu", 20, "cpu percentage of one core")
	lowerDir := fs.String("lowerdir", os.Getenv("OPERAX_LOWERDIR"), "read-only lowerdir for kernel backend")
	dryRun := fs.Bool("dry-run", false, "print resulting workspace spec and policy plan without creating")
	if err := fs.Parse(args); err != nil {
		a.logger.Error("restore parse failed", "err", err)
		return err
	}
	if *snapshotPath == "" {
		return fmt.Errorf("usage: operax restore --snapshot <path> [options]")
	}
	workspaceID := *id
	if workspaceID == "" {
		workspaceID = "ws-restore-" + randomID(4)
	}
	wsSpec := buildWorkspaceSpec(workspaceSpecInput{
		id:              workspaceID,
		tenant:          *tenant,
		ttl:             *ttl,
		cpuPercent:      *cpuPercent,
		memMB:           *memMB,
		netPolicy:       *netPolicy,
		allowCIDRs:      *allowCIDRs,
		profile:         *profile,
		lowerDir:        *lowerDir,
		command:         *command,
		restoreSnapshot: *snapshotPath,
		pidsMax:         256,
	})
	if *dryRun {
		return printDryRun(wsSpec)
	}

	a.logger.Info("restoring workspace from snapshot", "id", workspaceID, "snapshot", *snapshotPath)
	rec, err := a.orch.RestoreWorkspace(ctx, wsSpec)
	if err != nil {
		a.logger.Error("restore failed", "id", workspaceID, "err", err)
		a.metrics.RecordSnapshotFailed()
		return userFacingError(err)
	}
	a.metrics.RecordSnapshotRestored()
	fmt.Printf("Workspace restored: %s\n", rec.Workspace.ID)
	fmt.Println(spec.Pretty(rec))
	a.logger.Info("workspace restored successfully", "id", workspaceID)
	return nil
}

func (a *App) suspend(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: operax suspend <workspace-id>")
	}

	wsID := args[0]

	a.logger.Info("suspending workspace", "id", wsID)
	if err := a.orch.SuspendWorkspace(ctx, wsID); err != nil {
		a.logger.Error("suspend failed", "id", wsID, "err", err)
		return userFacingError(err)
	}
	a.logger.Info("workspace suspended successfully", "id", wsID)
	return nil
}

func (a *App) reap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reap", flag.ContinueOnError)
	once := fs.Bool("once", false, "run a single TTL sweep and exit")
	if err := fs.Parse(args); err != nil {
		a.logger.Error("reap parse failed", "err", err)
		return err
	}
	a.logger.Info("starting TTL reaper", "once", *once)

	// Create a standalone TTL reaper
	r := a.orch.NewTTLReaper()

	if *once {
		if err := r.ReapOnce(ctx); err != nil {
			a.logger.Error("reap once failed", "err", err)
			return err
		}
		a.logger.Info("reap sweep completed")
		return nil
	}
	return r.Run(ctx)
}

func (a *App) createAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create-agent", flag.ContinueOnError)
	id := fs.String("id", "", "workspace identifier")
	tenant := fs.String("tenant", "default", "tenant identifier")
	ttl := fs.Duration("ttl", 30*time.Minute, "workspace time to live")
	memMB := fs.Int64("mem", 4096, "memory limit in MiB (AI default: 4GB)")
	cpuPercent := fs.Int64("cpu", 100, "cpu percentage of one core (AI default: 100%)")
	profile := fs.String("profile", "default", "seccomp profile id")
	allowCIDRs := fs.String("allow-cidrs", "0.0.0.0/0", "comma-separated allowlist CIDRs for external APIs")
	command := fs.String("command", "/bin/sh", "command to run on attach")
	lowerDir := fs.String("lowerdir", os.Getenv("OPERAX_LOWERDIR"), "read-only lowerdir for kernel backend")
	snapshotOnExit := fs.Bool("snapshot-on-exit", false, "snapshot before destroy")
	restoreSnapshot := fs.String("restore", "", "restore workspace contents from snapshot tar")
	dryRun := fs.Bool("dry-run", false, "print resulting workspace spec and policy plan without creating")
	if err := fs.Parse(args); err != nil {
		a.logger.Error("create-agent parse failed", "err", err)
		return err
	}

	workspaceID := *id
	if workspaceID == "" {
		workspaceID = "ws-agent-" + randomID(4)
	}

	wsSpec := buildWorkspaceSpec(workspaceSpecInput{
		id:              workspaceID,
		tenant:          *tenant,
		ttl:             *ttl,
		cpuPercent:      *cpuPercent,
		memMB:           *memMB,
		netPolicy:       string(spec.NetworkAllowlist),
		allowCIDRs:      *allowCIDRs,
		profile:         *profile,
		lowerDir:        *lowerDir,
		command:         *command,
		snapshotOnExit:  *snapshotOnExit,
		restoreSnapshot: *restoreSnapshot,
		pidsMax:         512,
	})
	if *dryRun {
		return printDryRun(wsSpec)
	}

	a.logger.Info("creating AI agent workspace", "id", workspaceID, "tenant", *tenant)
	rec, err := a.orch.CreateWorkspace(ctx, wsSpec)
	if err != nil {
		a.logger.Error("create-agent failed", "id", workspaceID, "err", err)
		a.metrics.RecordWorkspaceFailed()
		return userFacingError(err)
	}
	a.metrics.RecordWorkspaceCreated()
	fmt.Printf("AI Agent workspace created: %s\n", rec.Workspace.ID)
	fmt.Printf("  Memory: %d MiB\n", *memMB)
	fmt.Printf("  CPU: %d%% of one core\n", *cpuPercent)
	fmt.Printf("  TTL: %v\n", *ttl)
	fmt.Printf("  Network: Allowlist (%s)\n", strings.Join(wsSpec.AllowedCIDRs, ", "))
	fmt.Println(spec.Pretty(rec))
	a.logger.Info("AI agent workspace created successfully", "id", workspaceID)
	return nil
}

func applyAIModeDefaults(fs *flag.FlagSet, ttl *time.Duration, cpuPercent, memMB *int64, netPolicy, allowCIDRs *string) {
	if !flagWasSet(fs, "mem") {
		*memMB = 4096
	}
	if !flagWasSet(fs, "cpu") {
		*cpuPercent = 100
	}
	if !flagWasSet(fs, "ttl") {
		*ttl = 30 * time.Minute
	}
	if !flagWasSet(fs, "net") {
		*netPolicy = "allowlist"
	}
	if *netPolicy == "allowlist" && !flagWasSet(fs, "allow-cidrs") && strings.TrimSpace(*allowCIDRs) == "" {
		*allowCIDRs = "0.0.0.0/0"
	}
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	wasSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			wasSet = true
		}
	})
	return wasSet
}

func randomID(bytesLen int) string {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(buf)
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func fmtDuration(d time.Duration) string {
	if d <= 0 {
		return "0s (EXPIRED)"
	}
	d = d.Round(time.Millisecond)
	return d.String()
}

func backendMode() string {
	mode := strings.TrimSpace(strings.ToLower(os.Getenv("OPERAX_BACKEND")))
	if mode == "" {
		return "auto"
	}
	return mode
}

type workspaceSpecInput struct {
	id              string
	tenant          string
	ttl             time.Duration
	cpuPercent      int64
	memMB           int64
	netPolicy       string
	allowCIDRs      string
	profile         string
	lowerDir        string
	command         string
	snapshotOnExit  bool
	restoreSnapshot string
	pidsMax         int64
}

func buildWorkspaceSpec(input workspaceSpecInput) spec.WorkspaceSpec {
	return spec.WorkspaceSpec{
		ID:               input.id,
		TenantID:         input.tenant,
		TTL:              input.ttl,
		CPUQuota:         input.cpuPercent * 10_000,
		CPUPeriod:        1_000_000,
		MemLimitBytes:    input.memMB * 1024 * 1024,
		NetworkPolicy:    spec.NetworkPolicy(input.netPolicy),
		AllowedCIDRs:     splitCSV(input.allowCIDRs),
		SeccompProfileID: input.profile,
		LowerDir:         input.lowerDir,
		Command:          strings.Fields(input.command),
		SnapshotOnExit:   input.snapshotOnExit,
		RestoreSnapshot:  input.restoreSnapshot,
		PidsMax:          input.pidsMax,
		Backend:          backendMode(),
	}
}

func printDryRun(wsSpec spec.WorkspaceSpec) error {
	if err := wsSpec.Validate(); err != nil {
		return userFacingError(err)
	}
	if err := policy.ValidateWorkspaceSpec(wsSpec); err != nil {
		return userFacingError(err)
	}
	fmt.Println("Dry run only: no workspace created.")
	fmt.Println(spec.Pretty(wsSpec))
	for _, note := range policy.ExplainWorkspaceSpec(wsSpec) {
		fmt.Printf("- %s\n", note)
	}
	return nil
}

func (a *App) explainPolicy(args []string) error {
	fs := flag.NewFlagSet("explain-policy", flag.ContinueOnError)
	id := fs.String("id", "ws-explain-"+randomID(4), "workspace identifier")
	tenant := fs.String("tenant", "default", "tenant identifier")
	ttl := fs.Duration("ttl", 60*time.Second, "workspace time to live")
	cpuPercent := fs.Int64("cpu", 20, "cpu percentage of one core")
	memMB := fs.Int64("mem", 512, "memory limit in MiB")
	netPolicy := fs.String("net", "none", "network policy: none, allowlist, open")
	allowCIDRs := fs.String("allow-cidrs", "", "comma-separated allowlist CIDRs")
	profile := fs.String("profile", "default", "seccomp profile id")
	command := fs.String("command", "/bin/sh", "command to evaluate")
	lowerDir := fs.String("lowerdir", os.Getenv("OPERAX_LOWERDIR"), "read-only lowerdir for kernel backend")
	if err := fs.Parse(args); err != nil {
		return err
	}
	wsSpec := buildWorkspaceSpec(workspaceSpecInput{
		id:         *id,
		tenant:     *tenant,
		ttl:        *ttl,
		cpuPercent: *cpuPercent,
		memMB:      *memMB,
		netPolicy:  *netPolicy,
		allowCIDRs: *allowCIDRs,
		profile:    *profile,
		lowerDir:   *lowerDir,
		command:    *command,
		pidsMax:    256,
	})
	if err := wsSpec.Validate(); err != nil {
		return userFacingError(err)
	}
	if err := policy.ValidateWorkspaceSpec(wsSpec); err != nil {
		return userFacingError(err)
	}
	fmt.Println(spec.Pretty(wsSpec))
	fmt.Println("Policy explanation:")
	for _, note := range policy.ExplainWorkspaceSpec(wsSpec) {
		fmt.Printf("- %s\n", note)
	}
	violations := policy.EvaluateCommand(wsSpec, 0)
	if len(violations) == 0 {
		fmt.Println("- heuristic command check: no denied syscall hints detected")
		return nil
	}
	fmt.Println("- heuristic command check: denied syscall hints detected")
	for _, v := range violations {
		fmt.Printf("  - syscall=%s result=%s\n", v.Syscall, v.Result)
	}
	return nil
}

func userFacingError(err error) error {
	var invalidSpec *apperrors.ErrInvalidWorkspaceSpec
	if errors.As(err, &invalidSpec) {
		return fmt.Errorf("%w. run with --dry-run to preview effective spec and policy", err)
	}
	var policyErr *apperrors.ErrPolicyViolation
	if errors.As(err, &policyErr) {
		return fmt.Errorf("%w. run with --dry-run to see explainable policy output", err)
	}
	return err
}

func ctxWithLogger(ctx context.Context) context.Context {
	return logging.WithContext(ctx)
}

func selectBackend(workspaceRoot, helperPath string) (provision.Provisioner, provision.ResourceManager, error) {
	mode := backendMode()
	switch mode {
	case "kernel":
		return newKernelBackend(workspaceRoot, helperPath)
	case "auto":
		if provision.KernelBackendAvailable() {
			return newKernelBackend(workspaceRoot, helperPath)
		}
		fallthrough
	case "local":
		prov, err := provision.NewLocalProvisioner(workspaceRoot)
		if err != nil {
			return nil, nil, err
		}
		return prov, provision.NewStaticResourceManager(), nil
	default:
		return nil, nil, fmt.Errorf("unsupported OPERAX_BACKEND %q", mode)
	}
}

func newKernelBackend(workspaceRoot, helperPath string) (provision.Provisioner, provision.ResourceManager, error) {
	if !provision.KernelBackendAvailable() {
		return nil, nil, fmt.Errorf("kernel backend requires linux, root privileges, and the commands unshare/nsenter/ip/nft/mount/umount")
	}
	kernelWorkspaceRoot := os.Getenv("OPERAX_KERNEL_WORKSPACE_ROOT")
	if kernelWorkspaceRoot == "" {
		kernelWorkspaceRoot = filepath.Join(os.TempDir(), "operax-kernel", "workspaces")
	}
	prov, err := provision.NewKernelProvisioner(kernelWorkspaceRoot, helperPath, os.Getenv("OPERAX_LOWERDIR"))
	if err != nil {
		return nil, nil, err
	}
	res, err := provision.NewKernelResourceManager(os.Getenv("OPERAX_CGROUP_ROOT"))
	if err != nil {
		return nil, nil, err
	}
	return prov, res, nil
}
