package qrlogin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	repoTenantID   = "11111111-1111-1111-1111-111111111111"
	repoOtherID    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	repoSessionID  = "22222222-2222-2222-2222-222222222222"
	repoPersonID   = "33333333-3333-3333-3333-333333333333"
	repoFirstTxnID = "b0000000-0000-0000-0000-000000000001"
)

// repoNow is when the seeded transactions were started.
var repoNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

func testRepository(t *testing.T) (*Repository, *bun.DB) {
	t.Helper()

	bdb := dbtest.Open(t, "qrlogin")
	log, _ := logger.NewObserved()
	return NewRepository(bdb, log), bdb
}

// seedTransaction writes one pending transaction of the tenant.
func seedTransaction(t *testing.T, repo *Repository, id, tenantID, sessionID, presentationID string) Transaction {
	t.Helper()

	row := Transaction{
		ID:                     id,
		TenantID:               tenantID,
		LoginSessionID:         repoSessionID,
		VerifierSessionID:      sessionID,
		VerifierPresentationID: presentationID,
		NonceHash:              "0000000000000000000000000000000000000000000000000000000000000000",
		State:                  StatePending,
		ExpiresAt:              repoNow.Add(TransactionTTL),
	}
	if err := repo.Insert(context.Background(), row); err != nil {
		t.Fatalf("seed the transaction: %v", err)
	}
	return row
}

// TestFindByVerifierRef covers the one read that names no tenant. The push
// arrives at a fixed address, so this read is what supplies the tenant.
func TestFindByVerifierRef(t *testing.T) {
	repo, _ := testRepository(t)
	seeded := seedTransaction(t, repo, repoFirstTxnID, repoTenantID, "verifier-session-1", "presentation-1")

	tests := []struct {
		name           string
		sessionID      string
		presentationID string
		wantErr        error
	}{
		{name: "by the session identifier", sessionID: "verifier-session-1"},
		{name: "by the presentation identifier", presentationID: "presentation-1"},
		{name: "by both", sessionID: "verifier-session-1", presentationID: "presentation-1"},
		{
			// A push that carries both, one of which is an identifier of the
			// verifier's own, still finds the row.
			name:           "by one that matches and one that does not",
			sessionID:      "an-identifier-of-the-verifier",
			presentationID: "presentation-1",
		},
		{name: "neither identifier", wantErr: ErrNotFound},
		{name: "an identifier of nothing", sessionID: "nothing", wantErr: ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row, err := repo.FindByVerifierRef(context.Background(), tt.sessionID, tt.presentationID)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("find by verifier reference: %v", err)
			}
			// The read answers the tenant every later call is scoped by.
			if row.ID != seeded.ID || row.TenantID != repoTenantID {
				t.Errorf("row = %+v, want %s of tenant %s", row, seeded.ID, repoTenantID)
			}
		})
	}
}

// TestInsertRefusesADuplicateIdentifier covers the replay defence. The unique
// keys are global, so the constraint refuses a replay and application code does
// not.
func TestInsertRefusesADuplicateIdentifier(t *testing.T) {
	repo, _ := testRepository(t)
	seedTransaction(t, repo, repoFirstTxnID, repoTenantID, "verifier-session-1", "presentation-1")

	tests := []struct {
		name           string
		tenantID       string
		sessionID      string
		presentationID string
	}{
		{
			name:           "the same session identifier in the same tenant",
			tenantID:       repoTenantID,
			sessionID:      "verifier-session-1",
			presentationID: "presentation-2",
		},
		{
			// The keys are global and not scoped to one tenant.
			name:           "the same presentation identifier in another tenant",
			tenantID:       repoOtherID,
			sessionID:      "verifier-session-2",
			presentationID: "presentation-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := Transaction{
				ID:                     "b0000000-0000-0000-0000-000000000009",
				TenantID:               tt.tenantID,
				LoginSessionID:         repoSessionID,
				VerifierSessionID:      tt.sessionID,
				VerifierPresentationID: tt.presentationID,
				NonceHash:              "0000000000000000000000000000000000000000000000000000000000000000",
				State:                  StatePending,
				ExpiresAt:              repoNow.Add(TransactionTTL),
			}
			if err := repo.Insert(context.Background(), row); err == nil {
				t.Error("the duplicate identifier was written, want a refusal")
			}
		})
	}
}

// TestConsume covers the guarded claim: a transaction is claimed once, and a
// second push changes nothing.
func TestConsume(t *testing.T) {
	repo, _ := testRepository(t)
	seedTransaction(t, repo, repoFirstTxnID, repoTenantID, "verifier-session-1", "presentation-1")
	ctx := context.Background()

	if err := repo.Consume(ctx, repoTenantID, repoFirstTxnID, repoNow); err != nil {
		t.Fatalf("the first claim: %v", err)
	}
	if err := repo.Consume(ctx, repoTenantID, repoFirstTxnID, repoNow); !errors.Is(err, ErrNotFound) {
		t.Errorf("the second claim gave %v, want %v", err, ErrNotFound)
	}
	// Another tenant cannot claim it either.
	if err := repo.Consume(ctx, repoOtherID, repoFirstTxnID, repoNow); !errors.Is(err, ErrNotFound) {
		t.Errorf("the claim of another tenant gave %v, want %v", err, ErrNotFound)
	}
}

// TestConsumeRefusesAnExpiredTransaction covers the window. A transaction the
// window has passed is never claimable.
func TestConsumeRefusesAnExpiredTransaction(t *testing.T) {
	repo, _ := testRepository(t)
	seedTransaction(t, repo, repoFirstTxnID, repoTenantID, "verifier-session-1", "presentation-1")

	after := repoNow.Add(TransactionTTL).Add(time.Second)
	if err := repo.Consume(context.Background(), repoTenantID, repoFirstTxnID, after); !errors.Is(err, ErrNotFound) {
		t.Errorf("the claim gave %v, want %v", err, ErrNotFound)
	}
}

// TestSetResultAndFindByLoginSession covers what the poll reads back.
func TestSetResultAndFindByLoginSession(t *testing.T) {
	repo, _ := testRepository(t)
	seedTransaction(t, repo, repoFirstTxnID, repoTenantID, "verifier-session-1", "presentation-1")
	ctx := context.Background()

	if err := repo.SetResult(ctx, repoTenantID, repoFirstTxnID, StateVerified, repoPersonID); err != nil {
		t.Fatalf("record the result: %v", err)
	}

	row, err := repo.FindByLoginSession(ctx, repoTenantID, repoSessionID)
	if err != nil {
		t.Fatalf("find by login session: %v", err)
	}
	if row.State != StateVerified || row.UserID != repoPersonID {
		t.Errorf("row = %+v, want verified and naming %s", row, repoPersonID)
	}

	// The read is scoped to the tenant.
	if _, err := repo.FindByLoginSession(ctx, repoOtherID, repoSessionID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the read of another tenant gave %v, want %v", err, ErrNotFound)
	}
}
