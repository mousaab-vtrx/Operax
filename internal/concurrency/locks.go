package concurrency

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// WorkspaceLocks provides per-workspace mutual exclusion locks.
// This prevents concurrent operations (like double-attach or concurrent destroy) on the same workspace.
type WorkspaceLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// New creates a new WorkspaceLocks instance.
func New() *WorkspaceLocks {
	return &WorkspaceLocks{
		locks: make(map[string]*sync.Mutex),
	}
}

// Lock acquires an exclusive lock for the given workspace ID and returns
// an unlock function that must be called to release the lock.
//
// Example usage:
//
//	unlock := locks.Lock(workspaceID)
//	defer unlock()
//	// perform operations on workspace safely
func (wl *WorkspaceLocks) Lock(id string) func() {
	wl.mu.Lock()
	if wl.locks[id] == nil {
		wl.locks[id] = &sync.Mutex{}
	}
	mu := wl.locks[id]
	wl.mu.Unlock()

	mu.Lock()
	return mu.Unlock
}

// TryLock attempts to acquire a lock for the given workspace ID.
// It returns a boolean indicating success and an unlock function if successful.
// The unlock function will be nil if the lock could not be acquired.
func (wl *WorkspaceLocks) TryLock(id string) (func(), bool) {
	wl.mu.Lock()
	if wl.locks[id] == nil {
		wl.locks[id] = &sync.Mutex{}
	}
	mu := wl.locks[id]
	wl.mu.Unlock()

	if mu.TryLock() {
		return mu.Unlock, true
	}
	return nil, false
}

// FileWorkspaceLocks provides cross-process workspace locking using flock.
// Lock files live under root/<workspace-id>.lock.
type FileWorkspaceLocks struct {
	root string
}

func NewFileLocks(root string) (*FileWorkspaceLocks, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FileWorkspaceLocks{root: root}, nil
}

func (fl *FileWorkspaceLocks) lockPath(id string) string {
	return filepath.Join(fl.root, fmt.Sprintf("%s.lock", id))
}

func (fl *FileWorkspaceLocks) Lock(id string) (func(), error) {
	f, err := os.OpenFile(fl.lockPath(id), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

type WorkspaceCoordinator struct {
	inproc *WorkspaceLocks
	file   *FileWorkspaceLocks
}

func NewCoordinator(lockRoot string) (*WorkspaceCoordinator, error) {
	fileLocks, err := NewFileLocks(lockRoot)
	if err != nil {
		return nil, err
	}
	return &WorkspaceCoordinator{
		inproc: New(),
		file:   fileLocks,
	}, nil
}

// Lock acquires both in-process and cross-process locks.
func (c *WorkspaceCoordinator) Lock(id string) (func(), error) {
	releaseInProc := c.inproc.Lock(id)
	releaseFile, err := c.file.Lock(id)
	if err != nil {
		releaseInProc()
		return nil, err
	}
	return func() {
		releaseFile()
		releaseInProc()
	}, nil
}
