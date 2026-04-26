package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"operax/internal/spec"
)

type Sink interface {
	WriteRecord(context.Context, spec.AuditRecord) error
}

type FileSink struct {
	root string
	mu   sync.Mutex
}

func NewFileSink(root string) (*FileSink, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FileSink{root: root}, nil
}

// WriteRecord writes an audit record using append-only JSONL format.
// Each workspace gets a .jsonl file where records are appended one per line.
// This ensures complete audit trail history is preserved and never overwritten.
func (s *FileSink) WriteRecord(_ context.Context, rec spec.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}

	// Open file in append mode, creating if necessary
	path := filepath.Join(s.root, rec.WorkspaceID+".jsonl")
	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0o644,
	)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer file.Close()

	// Write record as single JSON line
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	if _, err := file.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync audit file: %w", err)
	}
	rootFD, err := os.Open(s.root)
	if err == nil {
		_ = rootFD.Sync()
		_ = rootFD.Close()
	}

	return nil
}

// ReadRecords reads all audit records for a workspace from its JSONL file.
// Returns records in chronological order (oldest first).
func (s *FileSink) ReadRecords(_ context.Context, workspaceID string) ([]spec.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.root, workspaceID+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []spec.AuditRecord{}, nil
		}
		return nil, fmt.Errorf("read audit file: %w", err)
	}

	var records []spec.AuditRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue // Skip empty lines
		}
		var rec spec.AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("unmarshal audit record: %w", err)
		}
		records = append(records, rec)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan audit records: %w", err)
	}

	return records, nil
}

func (s *FileSink) RootDir() string {
	return s.root
}

func (s *FileSink) AuditPath(workspaceID string) string {
	return filepath.Join(s.root, workspaceID+".jsonl")
}
