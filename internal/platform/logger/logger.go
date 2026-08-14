package logger

import "go.uber.org/zap"

// Field is an alias for zap.Field so callers never import zap directly.
type Field = zap.Field

// Logger is the logging interface injected across all layers.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
	// With returns a child logger with the given fields pre-attached.
	With(fields ...Field) Logger
	// Sync flushes buffered entries. Call on graceful shutdown.
	Sync() error
}

// Field constructor helpers — use these instead of importing zap directly.
var (
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Duration = zap.Duration
	Any      = zap.Any
	Err      = zap.Error
	Stringer = zap.Stringer
)
