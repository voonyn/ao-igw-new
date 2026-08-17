package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// NewObserved returns a Logger that records every entry instead of writing it,
// and the recording it writes into. A test reads the recording to assert what a
// layer logged, and at which level.
//
// It exists so a test never reimplements the Logger interface. It records at
// debug, so the per-layer debug lines are visible to a test even though
// production runs at info.
func NewObserved() (Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return &zapLogger{z: zap.New(core)}, logs
}
