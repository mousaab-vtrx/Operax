package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Entry struct {
	WorkspaceID string    `json:"workspace_id"`
	StatePath   string    `json:"state_path"`
	AuditPath   string    `json:"audit_path"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Log struct {
	root string
}

func New(root string) (*Log, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &Log{root: root}, nil
}

func (l *Log) Begin(entry Entry) (string, error) {
	entry.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	path := filepath.Join(l.root, entry.WorkspaceID+".pending.json")
	tmp, err := os.CreateTemp(l.root, entry.WorkspaceID+".*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := syncDir(l.root); err != nil {
		return "", err
	}
	return path, nil
}

func (l *Log) Commit(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(l.root)
}

func (l *Log) Pending() ([]Entry, error) {
	entries, err := os.ReadDir(l.root)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pending.json") {
			continue
		}
		path := filepath.Join(l.root, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var parsed Entry
		if err := json.Unmarshal(data, &parsed); err != nil {
			continue
		}
		out = append(out, parsed)
	}
	return out, nil
}

func (l *Log) PendingPath(workspaceID string) string {
	return filepath.Join(l.root, workspaceID+".pending.json")
}

func syncDir(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	return fd.Sync()
}
