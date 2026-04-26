# Operax

Secure multi-tenant workspace orchestration for ephemeral, policy-controlled execution environments.

Operax helps you create short-lived workspaces with explicit security and resource policies, then track their full lifecycle with metrics and audit records.

---

## Table of Contents

- [What Problem Operax Solves](#what-problem-operax-solves)
- [What Operax Is](#what-operax-is)
- [Core Features](#core-features)
- [How Operax Works](#how-operax-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Policy Explainability and Dry Runs](#policy-explainability-and-dry-runs)
- [Thermal Throttling Model](#thermal-throttling-model)
- [Where Else Operax Is Useful](#where-else-operax-is-useful)
- [Architecture Overview](#architecture-overview)
- [Development](#development)
- [Limitations and Operational Notes](#limitations-and-operational-notes)

---

## What Problem Operax Solves

Teams running untrusted or mixed-trust workloads usually hit the same issues:

- **Unsafe execution**: one tenant can run commands that should never affect the host or other tenants.
- **Noisy neighbors**: CPU and memory spikes from one workload degrade everyone else.
- **Weak traceability**: teams cannot reliably answer who created, changed, or destroyed an environment.
- **Environment drift**: reproducibility suffers without snapshot/restore primitives.
- **Manual cleanup burden**: stale environments and abandoned resources accumulate over time.

Operax addresses this by combining lifecycle orchestration, security policy enforcement, and resource accounting in one CLI-driven control plane.

---

## What Operax Is

Operax is a Go application that provisions and manages isolated workspaces.

It supports:

- **Workspace lifecycle**: create, attach, inspect, suspend, snapshot, restore, destroy, TTL reaping.
- **Policy controls**: network policies (`none`, `allowlist`, `open`) and seccomp profiles (`default`, `strict`).
- **Resource controls**: CPU/memory limits and observed metrics.
- **Auditability**: append-only audit records with lifecycle events and metadata.
- **Backend modes**:
  - **`kernel`**: Linux namespace/cgroup/nftables/seccomp-backed enforcement.
  - **`local`**: lightweight local execution path for development/testing.
  - **`auto`**: prefer kernel backend when available.

---

## Core Features

- **Multi-tenant workspace isolation**
  - Tenant ID is tracked throughout state and audit records.
- **Policy-aware workspace specs**
  - Validation enforces supported policy combinations and seccomp profile existence.
- **Explainable policy output**
  - `explain-policy` and `--dry-run` show how your spec is interpreted before creation.
- **Crash-consistent persistence path**
  - State and audit writes are coordinated with a journal/recovery approach.
- **Cross-process coordination**
  - Workspace locking avoids concurrent destructive operations from multiple processes.
- **Snapshot and restore**
  - Capture workspace filesystem state and restore new workspaces from snapshots.
- **Thermal telemetry and adaptive throttling (local backend metrics path)**
  - Sustained high pressure marks a workspace as hot/critical and can reduce effective CPU quota in observed metrics.
- **TTL reaper**
  - Background or one-shot expiration cleanup for outdated workspaces.

---

## How Operax Works

1. CLI builds a `WorkspaceSpec` from your command inputs.
2. Spec + policy validation runs before provisioning.
3. Provisioner prepares workspace filesystem/runtime structures.
4. Resource manager applies limits and collects metrics.
5. State and audit data are persisted with recovery-aware coordination.
6. Lifecycle transitions are logged and queryable via CLI.

---

## Installation

### Prerequisites

- Go `1.22+`
- Linux recommended for full kernel backend capabilities
- Root/CAP_SYS_ADMIN for kernel backend operations

### Build

```bash
git clone https://github.com/operax/operax.git
cd operax
go build -o operax ./cmd/operax
```

### Optional install

```bash
sudo mv operax /usr/local/bin/
```

### Runtime environment variables

- `OPERAX_DATA_DIR`: root directory for state/audit/workspace metadata (default: `./.operax`)
- `OPERAX_BACKEND`: `auto`, `local`, or `kernel`
- `OPERAX_LOWERDIR`: read-only lowerdir used by kernel backend
- `OPERAX_KERNEL_WORKSPACE_ROOT`: kernel backend workspace root override
- `OPERAX_CGROUP_ROOT`: cgroup v2 root override for kernel backend

---

## Quick Start

```bash
# 1) Create a workspace (local backend example)
OPERAX_BACKEND=local operax create --id ws-demo --tenant demo --ttl 10m --mem 512 --cpu 30 --net none --command "/bin/bash"

# 2) List workspaces
operax list

# 3) Inspect one workspace
operax get ws-demo

# 4) Check metrics (includes thermal fields when available)
operax metrics ws-demo

# 5) Attach to workspace command
operax attach ws-demo

# 6) Destroy when done
operax destroy ws-demo
```

---

## Command Reference

### Lifecycle and Inspection

- `operax create [flags]`
- `operax create-agent [flags]`
- `operax attach <workspace-id>`
- `operax suspend <workspace-id>`
- `operax destroy <workspace-id>`
- `operax get <workspace-id>`
- `operax list [--offset N --limit N]`

### Observability and Compliance

- `operax metrics <workspace-id>`
- `operax audit <workspace-id>`

### State Operations

- `operax snapshot <workspace-id>`
- `operax restore --snapshot <path> [flags]`

### Maintenance

- `operax reap [--once]`

### Policy Tooling

- `operax explain-policy [flags]`

---

## Common Usage Patterns

### 1) Create with explicit security policy

```bash
operax create \
  --id ws-secure \
  --tenant finance \
  --ttl 45m \
  --profile strict \
  --net allowlist \
  --allow-cidrs "10.0.0.0/8,172.16.0.0/12" \
  --command "/bin/bash"
```

### 2) AI/agent-oriented workspace

```bash
operax create-agent \
  --id ws-agent \
  --tenant platform \
  --ttl 2h \
  --mem 4096 \
  --cpu 100 \
  --allow-cidrs "0.0.0.0/0"
```

### 3) Snapshot and restore

```bash
operax snapshot ws-secure
operax restore --id ws-restored --tenant finance --snapshot /path/to/snapshot.tar
```

### 4) Paginate large workspace sets

```bash
operax list --offset 0 --limit 50
operax list --offset 50 --limit 50
```

---

## Policy Explainability and Dry Runs

Use these before provisioning to reduce surprise failures in production workflows.

### `--dry-run` on create/restore/create-agent

```bash
operax create \
  --id ws-preview \
  --net allowlist \
  --allow-cidrs "10.0.0.0/8" \
  --profile strict \
  --dry-run
```

This prints the normalized spec and explainable policy notes without creating anything.

### `explain-policy` command

```bash
operax explain-policy \
  --id ws-explain \
  --tenant security \
  --net allowlist \
  --allow-cidrs "10.0.0.0/8,172.16.0.0/12" \
  --profile strict \
  --command "bash -lc 'echo hello'"
```

This prints:

- normalized workspace spec
- policy interpretation notes (network and seccomp context)
- heuristic command-line denied-syscall hints

---

## Thermal Throttling Model

Operax includes thermal telemetry fields in `metrics` output:

- `thermal_score`
- `thermal_state` (`cool`, `warm`, `hot`, `critical`)
- `thermal_throttled` (`true`/`false`)

In the local resource metrics path, sustained high memory/PID pressure can trigger adaptive observed CPU quota reduction to reduce noisy-neighbor risk.

---

## Where Else Operax Is Useful

Beyond standard multi-tenant dev sandboxes, Operax is useful for:

- **Secure code execution backends**
  - coding challenges, plugin sandboxes, user-generated script runners.
- **CI job isolation**
  - short-lived build/test environments with deterministic cleanup.
- **Data/ML experiment staging**
  - run controlled experiments with explicit network and TTL boundaries.
- **Security training and red/blue labs**
  - reproducible, isolated environments with auditable lifecycle traces.
- **Incident reproduction**
  - restore historical snapshots and replay known conditions safely.
- **Internal platform engineering**
  - ephemeral environments for preview deployments or debugging sessions.
- **Compliance-sensitive workloads**
  - strong operational traceability with workspace and tenant context.

---

## Architecture Overview

### Architecture Style and Pattern

Operax uses a **modular layered architecture** with a **hexagonal/ports-and-adapters flavor**:

- **Application/Core layer**: orchestration and lifecycle rules (`Orchestrator`).
- **Interface layer**: CLI command handling and argument normalization.
- **Infrastructure adapters**: provisioners, resource managers, file-backed state store, and audit sink.

The runtime composition follows a **control-plane orchestration pattern**, where one coordinator (`Orchestrator`) drives policy validation, provisioning, state transitions, and persistence.

### High-Level Flow

```text
CLI -> Orchestrator -> Provisioner/Resource Manager -> State Store + Audit Sink
```

### Design Patterns Used

- **Strategy pattern**
  - Backend behavior is selected via interchangeable implementations (`local`, `kernel`) behind `Provisioner` and `ResourceManager` interfaces.
- **Repository-like abstraction**
  - `StateStore` encapsulates persistence operations (`Save`, `Load`, `List`, `Delete`) independent of orchestration logic.
- **Adapter pattern**
  - Filesystem-backed state and audit components adapt infrastructure concerns to application interfaces.
- **Transaction/compensating actions**
  - Multi-step workspace creation uses rollback actions to unwind partial failures safely.
- **Write-ahead journaling**
  - Journal-mediated persistence improves crash consistency between state and audit writes.
- **Coordinator pattern**
  - `Orchestrator` and reaper coordinate lifecycle transitions across policy, runtime, and persistence.
- **Command pattern (CLI)**
  - Subcommands map to explicit handlers (`create`, `attach`, `restore`, etc.), each owning parsing and execution flow.

### Architecture Characteristics

- **Modularity**
  - Clear separation of concerns across CLI, orchestration, policy, provisioning, and persistence.
- **Extensibility**
  - Interface-driven backends make it straightforward to add new runtime or storage adapters.
- **Resilience**
  - Rollback and journal recovery reduce inconsistent state after partial failures or crashes.
- **Safety**
  - Cross-process workspace coordination and lifecycle guards reduce race conditions.
- **Secure design**
  - Policy validation, seccomp profile handling, and network policy controls are enforced in the orchestration path.
- **Observability**
  - Metrics, audit records, and lifecycle transitions provide strong debugging and compliance traceability.
- **Deterministic**
  - Explicit state transitions plus TTL reaping support predictable environment behavior at scale.

### Core Components

- **CLI layer**: command routing and argument parsing.
- **Orchestrator**: lifecycle control, policy checks, transitions, persistence coordination.
- **Provisioner**: local or kernel-backed workspace runtime management.
- **Resource manager**: limits, observations, metrics.
- **State store / audit sink**: persistent records and append-only audit events.
- **Reaper**: TTL-based cleanup loop.

---

## Development

### Build

```bash
go build -o operax ./cmd/operax
```

### Test

```bash
go test ./...
```

### Local-backend focused testing

```bash
OPERAX_BACKEND=local go test ./...
```

---

## Limitations and Operational Notes

- Local backend is intentionally lightweight and does **not** provide full kernel isolation guarantees.
- Some policy visibility is heuristic (for example command-line derived syscall hints) and not a full syscall event stream.
- Kernel backend is Linux-specific and depends on host capabilities/tools (`unshare`, `nsenter`, `ip`, `nft`, `mount`, `umount`).
- For production-grade multi-tenant setups, treat host hardening, access control, and external observability as first-class requirements around Operax.
