package authpolicy

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	enforceTenantID = "11111111-1111-1111-1111-111111111111"
	enforceOrgID    = "22222222-2222-2222-2222-222222222222"
)

// TestEnforceReadsTheOrganizationOverTheTenantDefault proves that the check runs
// against the level the person belongs to. The organization sets a minimum
// length of its own, and the password the tenant default admits is refused.
func TestEnforceReadsTheOrganizationOverTheTenantDefault(t *testing.T) {
	svc, _ := enforceService(t, map[string]Row{
		"":           {PwMinLength: ptr(8)},
		enforceOrgID: {PwMinLength: ptr(20)},
	})

	if err := svc.Enforce(context.Background(), enforceTenantID, "", "12345678"); err != nil {
		t.Errorf("err = %v for the tenant default, want the password admitted", err)
	}
	err := svc.Enforce(context.Background(), enforceTenantID, enforceOrgID, "12345678")
	if !errors.Is(err, ErrWeakPassword) {
		t.Errorf("err = %v for the organization, want ErrWeakPassword", err)
	}
}

// TestEnforceServesAPolicyThatAsksForABreachCheck proves the gap this deployment
// carries. No breach client is built, so a policy that asks for the check does
// not block the write, and the missing check is logged instead.
func TestEnforceServesAPolicyThatAsksForABreachCheck(t *testing.T) {
	svc, logs := enforceService(t, map[string]Row{
		"": {PwMinLength: ptr(8), PwCheckBreach: ptr(true)},
	})

	if err := svc.Enforce(context.Background(), enforceTenantID, "", "12345678"); err != nil {
		t.Fatalf("err = %v, want the write served", err)
	}
	if got := logs.FilterLevelExact(zapcore.WarnLevel).Len(); got != 1 {
		t.Fatalf("the service logged %d warnings, want one naming the missing breach client", got)
	}
}

// TestEnforceLogsAFailedPolicyReadOnceAndRefusesNothing proves that a read the
// database could not serve is logged here, where the tenant and the organization
// are still known, and that it never reads as a weak-password refusal. The
// mapper registers no rule for it, so the request answers a server error.
func TestEnforceLogsAFailedPolicyReadOnceAndRefusesNothing(t *testing.T) {
	down := errors.New("the database is down")
	svc, logs := enforceService(t, nil)
	svc.deps.Find = func(context.Context, string, string) (Row, error) { return Row{}, down }

	err := svc.Enforce(context.Background(), enforceTenantID, enforceOrgID, "12345678")
	if !errors.Is(err, down) {
		t.Fatalf("err = %v, want the error of the read", err)
	}
	if errors.Is(err, ErrWeakPassword) {
		t.Error("the failed read reads as a weak-password refusal, want a server error")
	}
	if got := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); got != 1 {
		t.Errorf("the service logged %d error lines, want exactly one", got)
	}
}

// TestEnforceKeepsThePasswordOutOfEveryLog reads every line the check wrote, at
// every level, on the path that refuses and on the path the read failed on.
func TestEnforceKeepsThePasswordOutOfEveryLog(t *testing.T) {
	const plain = "a-secret-password"

	svc, logs := enforceService(t, map[string]Row{"": {PwMinLength: ptr(64)}})
	_ = svc.Enforce(context.Background(), enforceTenantID, "", plain)

	svc.deps.Find = func(context.Context, string, string) (Row, error) {
		return Row{}, errors.New("the database is down")
	}
	_ = svc.Enforce(context.Background(), enforceTenantID, "", plain)

	for _, entry := range logs.All() {
		if entry.Message == plain {
			t.Errorf("the log line %q is the password", entry.Message)
		}
		for _, field := range entry.Context {
			if field.String == plain {
				t.Errorf("the log field %q carries the password", field.Key)
			}
		}
	}
}

// enforceService builds the service with the stored row of each level served
// from a map. Enforce reads that one dependency, so nothing else is wired.
func enforceService(t *testing.T, rows map[string]Row) (*Service, *observer.ObservedLogs) {
	t.Helper()

	log, logs := logger.NewObserved()
	svc := NewService(Deps{
		Find: func(_ context.Context, _, orgID string) (Row, error) {
			row, ok := rows[orgID]
			if !ok {
				return Row{}, ErrNotFound
			}
			return row, nil
		},
		Log: log,
	})
	return svc, logs
}
