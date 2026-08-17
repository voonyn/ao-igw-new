package tenant

import (
	"errors"
	"testing"
)

// TestListAllDomainsCarriesTheRemovedHosts covers the read behind the console's
// domain tab. A removed host is inactive and not deleted, so it must come back:
// the row still holds the globally unique host, and the operator puts it back
// from that list.
func TestListAllDomainsCarriesTheRemovedHosts(t *testing.T) {
	repo, ctx := testRepo(t)
	if _, err := repo.db.ExecContext(ctx,
		`INSERT INTO tenant_domains (domain, tenant_id, is_primary, is_verified, state)
		 VALUES ('extra.acme.com', ?, 0, 1, 2)`, testTenantID); err != nil {
		t.Fatalf("seed the removed domain: %v", err)
	}

	rows, err := repo.ListAllDomains(ctx, testTenantID)
	if err != nil {
		t.Fatalf("read every domain: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("the tenant reads %d domains, want the primary and the removed one", len(rows))
	}
	if !rows[0].IsPrimary || rows[0].Domain != "auth.acme.com" {
		t.Errorf("the first row reads %+v, want the primary host", rows[0])
	}
	if rows[1].Domain != "extra.acme.com" || rows[1].State != DomainStateInactive {
		t.Errorf("the second row reads %+v, want the removed host", rows[1])
	}

	// The live read answers only what serves requests, so the two reads differ.
	live, err := repo.ListDomains(ctx, testTenantID)
	if err != nil {
		t.Fatalf("read the live domains: %v", err)
	}
	if len(live) != 1 {
		t.Errorf("the live read answers %d domains, want the primary alone", len(live))
	}
}

// TestFindDomainSeesEveryClaimOnTheHost covers the read an add runs first. The
// host is the primary key, so a soft-deleted row still occupies it and an insert
// on that host would fail. The read must therefore see it.
func TestFindDomainSeesEveryClaimOnTheHost(t *testing.T) {
	repo, ctx := testRepo(t)

	row, err := repo.FindDomain(ctx, "old.acme.com")
	if err != nil {
		t.Fatalf("read the marked host: %v", err)
	}
	if row.TenantID != testTenantID {
		t.Errorf("the marked host reads tenant %q, want the seeded tenant", row.TenantID)
	}

	if _, err := repo.FindDomain(ctx, "nobody.acme.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("a host nobody holds reads %v, want ErrDomainNotFound", err)
	}
}

// TestInsertDomainMapsTheHost covers the add. A new host resolves to the tenant
// as soon as it is written, so the live read answers it.
func TestInsertDomainMapsTheHost(t *testing.T) {
	repo, ctx := testRepo(t)

	err := repo.InsertDomain(ctx, Domain{
		Domain: "new.acme.com", TenantID: testTenantID,
		IsVerified: true, State: DomainStateActive,
	})
	if err != nil {
		t.Fatalf("map the host: %v", err)
	}

	id, err := repo.TenantIDByDomain(ctx, "new.acme.com")
	if err != nil {
		t.Fatalf("resolve the new host: %v", err)
	}
	if id != testTenantID {
		t.Errorf("the new host resolves to %q, want the seeded tenant", id)
	}
}

// TestDeactivateDomainStopsTheHostResolving covers the remove. The row stays and
// the host stops resolving, so no other tenant can claim it.
func TestDeactivateDomainStopsTheHostResolving(t *testing.T) {
	repo, ctx := testRepo(t)
	if _, err := repo.db.ExecContext(ctx,
		`INSERT INTO tenant_domains (domain, tenant_id, is_primary, is_verified, state)
		 VALUES ('extra.acme.com', ?, 0, 1, 1)`, testTenantID); err != nil {
		t.Fatalf("seed the second domain: %v", err)
	}

	if err := repo.DeactivateDomain(ctx, testTenantID, "extra.acme.com"); err != nil {
		t.Fatalf("remove the host: %v", err)
	}
	if _, err := repo.TenantIDByDomain(ctx, "extra.acme.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("the removed host resolves %v, want ErrDomainNotFound", err)
	}

	row, err := repo.FindDomain(ctx, "extra.acme.com")
	if err != nil {
		t.Fatalf("read the removed host: %v", err)
	}
	if row.State != DomainStateInactive || row.TenantID != testTenantID {
		t.Errorf("the removed row reads %+v, want an inactive row of the seeded tenant", row)
	}
}

// TestDeactivateDomainRefusesAHostTheTenantDoesNotHold covers the tenant clause.
// One tenant cannot remove the host of another, and a host nobody holds answers
// the same way.
func TestDeactivateDomainRefusesAHostTheTenantDoesNotHold(t *testing.T) {
	repo, ctx := testRepo(t)

	err := repo.DeactivateDomain(ctx, otherTenantID, "auth.acme.com")
	if !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("the host of another tenant reads %v, want ErrDomainNotFound", err)
	}
	if err := repo.DeactivateDomain(ctx, testTenantID, "nobody.acme.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("a host nobody holds reads %v, want ErrDomainNotFound", err)
	}
}

// TestRestoreDomainClearsBothMarks covers re-adding a host the tenant removed.
// The row comes back to work whether it was marked by the state or by the
// soft-delete column.
func TestRestoreDomainClearsBothMarks(t *testing.T) {
	repo, ctx := testRepo(t)

	// old.acme.com carries the soft-delete mark, which the live read filters out.
	if err := repo.RestoreDomain(ctx, testTenantID, "old.acme.com"); err != nil {
		t.Fatalf("restore the host: %v", err)
	}

	id, err := repo.TenantIDByDomain(ctx, "old.acme.com")
	if err != nil {
		t.Fatalf("resolve the restored host: %v", err)
	}
	if id != testTenantID {
		t.Errorf("the restored host resolves to %q, want the seeded tenant", id)
	}
}

// TestReadBootstrapReadsTheSingleton covers the record the console renders. A
// deployment that was migrated but never bootstrapped answers the sentinel, so
// the console names the missing subsystem instead of rendering an empty record.
func TestReadBootstrapReadsTheSingleton(t *testing.T) {
	repo, ctx := testRepo(t)

	if _, err := repo.ReadBootstrap(ctx); !errors.Is(err, ErrNoBootstrapRecord) {
		t.Errorf("an unbootstrapped deployment reads %v, want ErrNoBootstrapRecord", err)
	}

	if _, err := repo.db.ExecContext(ctx,
		`INSERT INTO system_bootstrap (id, tenant_id, version) VALUES (1, ?, '1.0.0')`,
		testTenantID); err != nil {
		t.Fatalf("seed the bootstrap record: %v", err)
	}

	row, err := repo.ReadBootstrap(ctx)
	if err != nil {
		t.Fatalf("read the bootstrap record: %v", err)
	}
	if row.ID != 1 || row.TenantID != testTenantID || row.Version != "1.0.0" {
		t.Errorf("the record reads %+v, want the seeded singleton", row)
	}
	if row.AppliedAt.IsZero() {
		t.Error("the record carries no applied_at, want the moment the routine ran")
	}
}
