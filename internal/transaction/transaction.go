package transaction

import (
	"fmt"
	"sync"
)

// Transaction provides rollback capability for multi-step operations.
// It collects cleanup actions and executes them in reverse order if needed.
type Transaction struct {
	mu       sync.Mutex
	rollback []func() error // Stack of cleanup actions (LIFO)
	name     string
}

// New creates a new transaction with a descriptive name for logging.
func New(name string) *Transaction {
	return &Transaction{
		name:     name,
		rollback: make([]func() error, 0),
	}
}

// OnRollback registers a cleanup function to be called if Rollback() is invoked.
// Cleanup functions are called in reverse order (LIFO - Last In, First Out).
// This ensures proper cleanup dependency ordering (e.g., unbind before destroy).
func (t *Transaction) OnRollback(cleanup func() error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollback = append(t.rollback, cleanup)
}

// Rollback executes all registered cleanup functions in reverse order.
// If a cleanup function fails, it logs the error but continues with remaining cleanups
// to ensure all resources are attempted to be freed.
// Returns a MultiError if multiple cleanups failed, or nil if all succeeded.
func (t *Transaction) Rollback() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.rollback) == 0 {
		return nil
	}

	var errors []error
	// Execute cleanups in reverse order (LIFO)
	for i := len(t.rollback) - 1; i >= 0; i-- {
		if err := t.rollback[i](); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return &MultiError{
			Transaction: t.name,
			Errors:      errors,
		}
	}
	return nil
}

// Commit marks the transaction as successful and clears rollback actions.
// Call this after all steps complete successfully.
func (t *Transaction) Commit() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollback = nil
}

// MultiError represents multiple errors that occurred during rollback.
type MultiError struct {
	Transaction string
	Errors      []error
}

func (e *MultiError) Error() string {
	msg := fmt.Sprintf("transaction %q rollback encountered %d errors:", e.Transaction, len(e.Errors))
	for i, err := range e.Errors {
		msg += fmt.Sprintf("\n  [%d] %v", i+1, err)
	}
	return msg
}

// Is allows checking if a MultiError is returned by wrapping errors.
func (e *MultiError) Is(target error) bool {
	_, ok := target.(*MultiError)
	return ok
}
