package totp

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
)

// The service composes its reads from function values, so the rules below are
// proved with no database. The flow test drives the same three addresses over
// HTTP, and it needs MySQL and Redis, so it skips on a plain go test.
//
// AccountStatus is what this file proves. AccountStart and AccountActivate are
// the shared body the sign-in path already runs, and the flow test measures the
// two against each other.

const (
	statusTenantID = "11111111-1111-1111-1111-111111111111"
	statusUserID   = "33333333-3333-3333-3333-333333333333"
)

// statusService builds a service whose reads answer what the test names. counted
// reports whether the Recovery Codes were counted at all.
func statusService(row Enrolment, find error, remaining int) (*Service, *bool) {
	counted := false
	return NewService(Deps{
		Find: func(context.Context, string, string) (Enrolment, error) {
			return row, find
		},
		CountRecoveryCodes: func(context.Context, string, string) (int, error) {
			counted = true
			return remaining, nil
		},
		Log: logger.New(),
	}), &counted
}

func TestAccountStatus(t *testing.T) {
	activated := time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC)

	tests := []struct {
		name      string
		row       Enrolment
		find      error
		remaining int

		want    Status
		counted bool
	}{
		{
			// The normal state of an account that never enrolled. It is not an
			// error, and the count is not read: no row can hold a code.
			name: "no row reads as no factor",
			find: ErrNoEnrolment,
		},
		{
			// A start mints this row and records no factor. A page that called
			// it active would tell the person they are protected when nobody
			// has proved a code with the secret.
			name: "a pending enrolment reads as no factor",
			row:  Enrolment{TenantID: statusTenantID, UserID: statusUserID},
		},
		{
			name:      "an active factor reads its activation and its codes",
			row:       Enrolment{TenantID: statusTenantID, UserID: statusUserID, ActivatedAt: activated},
			remaining: 10,
			want:      Status{Active: true, ActivatedAt: activated, RecoveryRemaining: 10},
			counted:   true,
		},
		{
			// Nine spent codes leave one. The page states what the database
			// holds, so the count is read on every answer and never assumed.
			name:      "a spent set reads what is left",
			row:       Enrolment{TenantID: statusTenantID, UserID: statusUserID, ActivatedAt: activated},
			remaining: 1,
			want:      Status{Active: true, ActivatedAt: activated, RecoveryRemaining: 1},
			counted:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, counted := statusService(tc.row, tc.find, tc.remaining)

			got, err := svc.AccountStatus(t.Context(), statusTenantID, Principal{UserID: statusUserID})
			if err != nil {
				t.Fatalf("AccountStatus: %v", err)
			}
			if got != tc.want {
				t.Errorf("status is %+v, want %+v", got, tc.want)
			}
			if *counted != tc.counted {
				t.Errorf("counted the recovery codes: %v, want %v", *counted, tc.counted)
			}
		})
	}
}

// TestAccountStatusFailedRead proves that a read nobody could answer is not
// reported as an account holding no factor. A page told "off" on a failed read
// would invite a person to enrol a factor they already hold.
func TestAccountStatusFailedRead(t *testing.T) {
	broken := errors.New("the database is unreachable")
	svc, _ := statusService(Enrolment{}, broken, 0)

	if _, err := svc.AccountStatus(t.Context(), statusTenantID, Principal{UserID: statusUserID}); !errors.Is(err, broken) {
		t.Errorf("error is %v, want %v", err, broken)
	}
}
