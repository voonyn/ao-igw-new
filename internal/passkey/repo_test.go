package passkey

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The SQL behind a Passkey a person removes and registers again.
//
// The primary key is (tenant_id, credential_id), so a removed row still holds
// the id of the device. Two rules follow from that, and both are proved here:
// the revive takes the row back, and the same id under another tenant is a
// different row.

const (
	repoTenantID = "11111111-1111-1111-1111-111111111111"
	repoOtherTen = "99999999-9999-9999-9999-999999999999"
	repoUserID   = "33333333-3333-3333-3333-333333333333"
	repoOtherID  = "44444444-4444-4444-4444-444444444444"
)

// repoCredID is the credential id every row below carries. One id under two
// tenants is what proves the scope.
var repoCredID = []byte{0x01, 0x02, 0x03}

// testRepository opens a scratch schema and seeds one Passkey on each of three
// accounts: two people of one tenant, and one person of another tenant.
func testRepository(t *testing.T) (*Repository, *bun.DB, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "passkey")
	ctx := context.Background()

	log, _ := logger.NewObserved()
	repo := NewRepository(bdb, log)

	seed := func(tenantID, userID string, credID []byte) {
		t.Helper()
		row := Credential{
			TenantID:     tenantID,
			CredentialID: credID,
			UserID:       userID,
			RPID:         "example.com",
			Record:       `{"id":"AQID"}`,
			Name:         "Laptop",
			CreatedAt:    time.Now().UTC(),
		}
		if err := repo.Insert(ctx, row); err != nil {
			t.Fatalf("seed the passkey of user %s: %v", userID, err)
		}
	}

	seed(repoTenantID, repoUserID, repoCredID)
	seed(repoTenantID, repoOtherID, []byte{0x0a})
	seed(repoOtherTen, repoUserID, repoCredID)

	return repo, bdb, ctx
}

// TestRepository_RemoveThenRevive proves the whole life of one row: a removal
// hides it from every read, and a later registration of the same device takes
// the row back.
func TestRepository_RemoveThenRevive(t *testing.T) {
	repo, _, ctx := testRepository(t)

	if err := repo.Delete(ctx, repoTenantID, repoUserID, repoCredID); err != nil {
		t.Fatalf("the delete answered %v, want nil", err)
	}

	rows, err := repo.List(ctx, repoTenantID, repoUserID)
	if err != nil {
		t.Fatalf("the list answered %v, want the live rows", err)
	}
	if len(rows) != 0 {
		t.Errorf("the list answered %d rows after the removal, want none", len(rows))
	}

	// The row stays behind the delete mark. It is what tells a later
	// registration of the same device that it may take the id back.
	removed, err := repo.FindByCredential(ctx, repoTenantID, repoCredID)
	if err != nil {
		t.Fatalf("the find answered %v, want the removed row", err)
	}
	if removed.DeletedAt.IsZero() {
		t.Error("the removed row carries no delete mark")
	}

	// A second removal touches nothing, because the row is no longer live.
	if err := repo.Delete(ctx, repoTenantID, repoUserID, repoCredID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the second delete answered %v, want %v", err, ErrNotFound)
	}

	back := Credential{
		TenantID:     repoTenantID,
		CredentialID: repoCredID,
		UserID:       repoUserID,
		RPID:         "example.com",
		Record:       `{"id":"AQID","new":true}`,
		Name:         "Work laptop",
		CreatedAt:    time.Now().UTC(),
	}
	if err := repo.Revive(ctx, back); err != nil {
		t.Fatalf("the revive answered %v, want nil", err)
	}

	rows, err = repo.List(ctx, repoTenantID, repoUserID)
	if err != nil {
		t.Fatalf("the list answered %v, want the live rows", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the list answered %d rows after the revive, want one", len(rows))
	}
	if rows[0].Name != "Work laptop" {
		t.Errorf("the revived row is named %q, want %q", rows[0].Name, "Work laptop")
	}
	// MySQL normalises the whitespace of a JSON column, so the blob is read for
	// the field the new registration added and not compared byte for byte.
	if !strings.Contains(rows[0].Record, `"new"`) {
		t.Errorf("the revived row holds %q, want the new blob", rows[0].Record)
	}
	if !rows[0].LastUsedAt.IsZero() {
		t.Error("the revived row remembers a last use, want none")
	}
}

// TestRepository_TheWritesAreScoped proves that a rename and a removal reach one
// row of one person of one tenant.
//
// The same credential id exists under another tenant, and another person of this
// tenant holds a Passkey of their own. Neither may move.
func TestRepository_TheWritesAreScoped(t *testing.T) {
	repo, _, ctx := testRepository(t)

	if err := repo.Rename(ctx, repoTenantID, repoUserID, repoCredID, "Renamed"); err != nil {
		t.Fatalf("the rename answered %v, want nil", err)
	}

	// The same id under the other tenant is a different row.
	other, err := repo.FindByCredential(ctx, repoOtherTen, repoCredID)
	if err != nil {
		t.Fatalf("the find in the other tenant answered %v, want the row", err)
	}
	if other.Name != "Laptop" {
		t.Errorf("the row of the other tenant is named %q, want %q", other.Name, "Laptop")
	}

	// A person cannot rename a Passkey they do not hold.
	if err := repo.Rename(
		ctx, repoTenantID, repoOtherID, repoCredID, "Stolen",
	); !errors.Is(err, ErrNotFound) {
		t.Errorf("the rename by another person answered %v, want %v", err, ErrNotFound)
	}

	// A person cannot remove a Passkey they do not hold.
	if err := repo.Delete(
		ctx, repoTenantID, repoOtherID, repoCredID,
	); !errors.Is(err, ErrNotFound) {
		t.Errorf("the delete by another person answered %v, want %v", err, ErrNotFound)
	}

	rows, err := repo.List(ctx, repoTenantID, repoUserID)
	if err != nil {
		t.Fatalf("the list answered %v, want the live rows", err)
	}
	if len(rows) != 1 || rows[0].Name != "Renamed" {
		t.Errorf("the list answered %v, want one row named Renamed", rows)
	}
}

// TestRepository_FindByCredentialAnswersNotFound proves the answer for a device
// this tenant never saw. It is the normal answer on a first registration.
func TestRepository_FindByCredentialAnswersNotFound(t *testing.T) {
	repo, _, ctx := testRepository(t)

	if _, err := repo.FindByCredential(
		ctx, repoTenantID, []byte{0xff, 0xfe},
	); !errors.Is(err, ErrNotFound) {
		t.Errorf("the find answered %v, want %v", err, ErrNotFound)
	}
}
