package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"go.uber.org/zap/zapcore"

	"alphaomega/identitygateway/internal/platform/logger"
)

// TestErrorLogger_LogsTheCodeNotTheText covers the credential rule. The
// protocol engine writes the description, and a description can quote the value
// that failed, which is sometimes a code or a token. The log line therefore
// carries the error code this package names, never the text the engine wrote.
func TestErrorLogger_LogsTheCodeNotTheText(t *testing.T) {
	const secret = "SplxlOBeZQQYbYS6WxSbIA"

	log, logs := logger.NewObserved()
	ErrorLogger(testTenantID, log)(context.Background(),
		goidc.NewError(goidc.ErrorCodeInvalidGrant, "authorization code "+secret+" was already used"))

	entries := logs.FilterLevelExact(zapcore.ErrorLevel).All()
	if len(entries) != 1 {
		t.Fatalf("the engine failure logged %d error lines, want 1", len(entries))
	}

	fields := entries[0].ContextMap()
	if fields["error_code"] != string(goidc.ErrorCodeInvalidGrant) {
		t.Errorf("the line carries error_code %v, want %q", fields["error_code"], goidc.ErrorCodeInvalidGrant)
	}
	if fields["tenant_id"] != testTenantID {
		t.Errorf("the line carries tenant_id %v, want %q", fields["tenant_id"], testTenantID)
	}
	if line := entries[0].Message + fieldText(fields); strings.Contains(line, secret) {
		t.Errorf("the line quotes the engine description, which held a credential: %s", line)
	}
}

// TestErrorLogger_UnknownError covers a failure the engine did not shape as a
// protocol error. There is no code to log, so the line says so and still says
// nothing the engine wrote.
func TestErrorLogger_UnknownError(t *testing.T) {
	log, logs := logger.NewObserved()
	ErrorLogger(testTenantID, log)(context.Background(), errors.New("dial tcp: connection refused"))

	entries := logs.FilterLevelExact(zapcore.ErrorLevel).All()
	if len(entries) != 1 {
		t.Fatalf("the engine failure logged %d error lines, want 1", len(entries))
	}
	if got := entries[0].ContextMap()["error_code"]; got != unknownErrorCode {
		t.Errorf("the line carries error_code %v, want %q", got, unknownErrorCode)
	}
	if line := fieldText(entries[0].ContextMap()); strings.Contains(line, "connection refused") {
		t.Errorf("the line quotes the underlying error text: %s", line)
	}
}

// fieldText renders the fields of one log line, so a test can search the whole
// line for a value that must never appear.
func fieldText(fields map[string]any) string {
	return fmt.Sprint(fields)
}
