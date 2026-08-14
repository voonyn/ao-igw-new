package logger

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DeRuina/timberjack"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type zapLogger struct {
	z *zap.Logger
}

// New builds a Logger from viper config:
//
//	Log.Level       — debug|info|warn|error  (default: info)
//	Log.File        — log file path           (default: logs/app.log)
//	App.Environment — "production" → JSON console encoding
func New() Logger {
	level := parseLevel(viper.GetString("Log.Level"))

	env := strings.ToLower(viper.GetString("App.Environment"))

	var encCfg zapcore.EncoderConfig
	if env == "production" {
		encCfg = zap.NewProductionEncoderConfig()
	} else {
		encCfg = zap.NewDevelopmentEncoderConfig()
	}
	encCfg.TimeKey = "time"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	cores := []zapcore.Core{
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(encCfg),
			zapcore.AddSync(os.Stdout),
			level,
		),
	}

	// Skip the rotating file sink under `go test`: each package's tests run with
	// their own working directory, so a relative logs/app.log would scatter a
	// logs/ dir into every tested package. Tests get stdout only; Log.File is
	// resolved relative to the server's CWD (repo root for `go run . server`).
	if !testing.Testing() {
		filePath := viper.GetString("Log.File")
		if filePath == "" {
			filePath = "logs/app.log"
		}
		cores = append(cores, zapcore.NewCore(
			zapcore.NewJSONEncoder(encCfg),
			zapcore.AddSync(&timberjack.Logger{
				Filename:         filePath,
				MaxSize:          100,
				MaxBackups:       7,
				MaxAge:           30,
				LocalTime:        true,
				Compression:      "gzip",
				RotationInterval: 24 * time.Hour,
				RotateAt:         []string{"00:00"},
			}),
			level,
		))
	}

	z := zap.New(
		zapcore.NewTee(cores...),
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	return &zapLogger{z: z}
}

func parseLevel(s string) zapcore.Level {
	switch strings.ToLower(s) {
	case "debug":
		return zapcore.DebugLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

func (l *zapLogger) Debug(msg string, fields ...Field) { l.z.Debug(msg, fields...) }
func (l *zapLogger) Info(msg string, fields ...Field)  { l.z.Info(msg, fields...) }
func (l *zapLogger) Warn(msg string, fields ...Field)  { l.z.Warn(msg, fields...) }
func (l *zapLogger) Error(msg string, fields ...Field) { l.z.Error(msg, fields...) }
func (l *zapLogger) Fatal(msg string, fields ...Field) { l.z.Fatal(msg, fields...) }
func (l *zapLogger) Sync() error                       { return l.z.Sync() }

func (l *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{z: l.z.With(fields...)}
}
