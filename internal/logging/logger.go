package logging

import (
	"context"
	"log/slog"
	"os"
	"sync"
)

var (
	defaultLogger *slog.Logger
	once          sync.Once
)

// Init initializes the global logger with JSON output to stderr.
// Should be called once at application startup. It's safe to call
// multiple times; subsequent calls are no-ops.
func Init() {
	once.Do(func() {
		opts := &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}
		handler := slog.NewJSONHandler(os.Stderr, opts)
		defaultLogger = slog.New(handler)
	})
}

// GetLogger returns the global logger instance.
// If Init() has not been called, it will be called automatically.
func GetLogger() *slog.Logger {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger
}

// WithContext adds the logger to the context for downstream use.
// This allows functions to retrieve the logger via FromContext().
func WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, loggerKey, GetLogger())
}

// FromContext retrieves the logger from context, or returns the default logger
// if no logger was set in the context.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return GetLogger()
}

type contextKey string

const loggerKey contextKey = "logger"

// Info logs an info-level message with attributes.
func Info(msg string, args ...any) {
	GetLogger().Info(msg, args...)
}

// Warn logs a warning-level message with attributes.
func Warn(msg string, args ...any) {
	GetLogger().Warn(msg, args...)
}

// Error logs an error-level message with attributes.
func Error(msg string, args ...any) {
	GetLogger().Error(msg, args...)
}

// Debug logs a debug-level message with attributes.
func Debug(msg string, args ...any) {
	GetLogger().Debug(msg, args...)
}
