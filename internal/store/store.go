package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"operax/internal/pagination"
	"operax/internal/spec"
)

type StateStore interface {
	Save(context.Context, spec.StateRecord) error
	Load(context.Context, string) (spec.StateRecord, error)
	Delete(context.Context, string) error
	List(context.Context) ([]spec.StateRecord, error)
	ListPaginated(context.Context, pagination.PageInfo) (pagination.Result[spec.StateRecord], error)
}

type FileStore struct {
	root string
	mu   sync.RWMutex
}

func NewFileStore(root string) (*FileStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) recordPath(id string) string {
	return filepath.Join(s.root, id+".json")
}

func (s *FileStore) Save(_ context.Context, rec spec.StateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	target := s.recordPath(rec.Workspace.ID)
	tmp, err := os.CreateTemp(s.root, rec.Workspace.ID+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	rootFD, err := os.Open(s.root)
	if err == nil {
		_ = rootFD.Sync()
		_ = rootFD.Close()
	}
	return nil
}

func (s *FileStore) Load(_ context.Context, id string) (spec.StateRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.recordPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return spec.StateRecord{}, ErrNotFound
		}
		return spec.StateRecord{}, err
	}

	var rec spec.StateRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return spec.StateRecord{}, err
	}
	return rec, nil
}

func (s *FileStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.recordPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

func (s *FileStore) List(_ context.Context) ([]spec.StateRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}

	var out []spec.StateRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, entry.Name()))
		if err != nil {
			return nil, err
		}
		var rec spec.StateRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Workspace.CreatedAt.Before(out[j].Workspace.CreatedAt)
	})
	return out, nil
}

// ListPaginated returns a paginated subset of state records with total count.
// This enables efficient browsing of large workload sets without loading all records.
func (s *FileStore) ListPaginated(_ context.Context, page pagination.PageInfo) (pagination.Result[spec.StateRecord], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.root)
	if err != nil {
		return pagination.Result[spec.StateRecord]{}, err
	}

	var all []spec.StateRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, entry.Name()))
		if err != nil {
			continue // Skip unreadable files
		}
		var rec spec.StateRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue // Skip malformed files
		}
		all = append(all, rec)
	}

	// Sort by creation time (consistent ordering)
	sort.Slice(all, func(i, j int) bool {
		return all[i].Workspace.CreatedAt.Before(all[j].Workspace.CreatedAt)
	})

	total := len(all)

	// Validate page parameters
	page = pagination.NewPageInfo(page.Offset, page.Limit)

	// Extract page slice
	end := page.Offset + page.Limit
	if end > total {
		end = total
	}

	var items []spec.StateRecord
	if page.Offset < total {
		items = all[page.Offset:end]
	}

	return pagination.NewResult(items, total, page.Offset, page.Limit), nil
}

var ErrNotFound = errors.New("state record not found")

func (s *FileStore) RootDir() string {
	return s.root
}

func (s *FileStore) RecordPath(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("workspace id is required")
	}
	return s.recordPath(id), nil
}
