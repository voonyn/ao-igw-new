package audit

import (
	"context"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The two tenants every repository test reads. The second one holds a row of
// its own, so a read that forgot its tenant predicate fails here.
const (
	repoTenantID  = "t-1"
	otherTenantID = "t-2"
)

// feedStart is the moment the seeded trail begins. The rows sit one hour apart,
// so a time range can name a boundary exactly.
var feedStart = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

// seedFeed writes the trail every repository test reads: three events of one
// tenant, and one of another.
func seedFeed(t *testing.T, repo *Repository, ctx context.Context) {
	t.Helper()

	rows := []Event{
		{
			ID: "e-1", TenantID: repoTenantID, ActorID: "u-1",
			Action: string(ActionOrgCreated), EntityType: EntityOrganization, EntityID: "o-1",
			Result: ResultSuccess, CreatedAt: feedStart,
		},
		{
			ID: "e-2", TenantID: repoTenantID, ActorID: "u-2",
			Action: string(ActionUserDeleted), EntityType: EntityUser, EntityID: "u-9",
			Result: ResultSuccess, CreatedAt: feedStart.Add(time.Hour),
		},
		{
			ID: "e-3", TenantID: repoTenantID, ActorID: "u-1",
			Action: string(ActionUserDeleted), EntityType: EntityUser, EntityID: "u-8",
			Result: ResultSuccess, CreatedAt: feedStart.Add(2 * time.Hour),
		},
		{
			ID: "e-4", TenantID: otherTenantID, ActorID: "u-1",
			Action: string(ActionOrgCreated), EntityType: EntityOrganization, EntityID: "o-1",
			Result: ResultSuccess, CreatedAt: feedStart.Add(3 * time.Hour),
		},
	}
	for _, row := range rows {
		if err := repo.Insert(ctx, row); err != nil {
			t.Fatalf("seed audit event %s: %v", row.ID, err)
		}
	}
}

func testFeedRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "audit")
	repo, ctx := NewRepository(bdb, logger.New()), context.Background()
	seedFeed(t, repo, ctx)
	return repo, ctx
}

// ids names the rows one read answered, in the order it answered them.
func ids(rows []Event) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ID)
	}
	return out
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestListEventsReadsTheTenantNewestFirst covers the default order and the
// tenant predicate. The trail of another tenant is not readable here.
func TestListEventsReadsTheTenantNewestFirst(t *testing.T) {
	repo, ctx := testFeedRepo(t)

	rows, total, err := repo.ListEvents(ctx, repoTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if total != 3 {
		t.Errorf("the read counts %d events, want the 3 of this tenant", total)
	}
	if want := []string{"e-3", "e-2", "e-1"}; !equal(ids(rows), want) {
		t.Errorf("the read answers %v, want %v", ids(rows), want)
	}
}

// TestListEventsNarrowsByEachFilter covers the five predicates the console
// sends. They are conjoined, so the last case names two of them.
func TestListEventsNarrowsByEachFilter(t *testing.T) {
	repo, ctx := testFeedRepo(t)

	cases := []struct {
		name string
		q    Query
		want []string
	}{
		{"actor", Query{Actor: "u-1"}, []string{"e-3", "e-1"}},
		{"action", Query{Action: string(ActionUserDeleted)}, []string{"e-3", "e-2"}},
		{"entity type", Query{EntityType: EntityOrganization}, []string{"e-1"}},
		{"entity id", Query{EntityID: "u-9"}, []string{"e-2"}},
		{"actor and action", Query{Actor: "u-1", Action: string(ActionUserDeleted)}, []string{"e-3"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.q.Limit = 20
			rows, total, err := repo.ListEvents(ctx, repoTenantID, c.q)
			if err != nil {
				t.Fatalf("read the trail: %v", err)
			}
			if !equal(ids(rows), c.want) {
				t.Errorf("the read answers %v, want %v", ids(rows), c.want)
			}
			if total != int64(len(c.want)) {
				t.Errorf("the read counts %d events, want %d", total, len(c.want))
			}
		})
	}
}

// TestListEventsBoundsTheTimeRange covers the range. From is inclusive and To is
// exclusive, so two adjacent ranges neither drop an event nor report one twice.
func TestListEventsBoundsTheTimeRange(t *testing.T) {
	repo, ctx := testFeedRepo(t)

	rows, total, err := repo.ListEvents(ctx, repoTenantID, Query{
		From: feedStart, To: feedStart.Add(time.Hour), Limit: 20,
	})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if want := []string{"e-1"}; !equal(ids(rows), want) || total != 1 {
		t.Errorf("the read answers %v and total %d, want %v and 1", ids(rows), total, want)
	}
}

// TestListEventsPagesByOffsetAndCountsTheWholeMatch covers the page. The count
// is of everything the filters match, because the console renders a pager from
// it and not from the page it is holding.
func TestListEventsPagesByOffsetAndCountsTheWholeMatch(t *testing.T) {
	repo, ctx := testFeedRepo(t)

	rows, total, err := repo.ListEvents(ctx, repoTenantID, Query{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if want := []string{"e-1"}; !equal(ids(rows), want) {
		t.Errorf("the last page answers %v, want %v", ids(rows), want)
	}
	if total != 3 {
		t.Errorf("the last page counts %d events, want the whole 3", total)
	}
}

// TestListEventsSortsOldestFirstOnRequest covers the one sort key the route
// offers. Migration 00025 indexes (tenant_id, created_at), and no other column
// of this table is indexed for an ordering.
func TestListEventsSortsOldestFirstOnRequest(t *testing.T) {
	repo, ctx := testFeedRepo(t)

	rows, _, err := repo.ListEvents(ctx, repoTenantID, Query{Sort: "created", Desc: false, Limit: 20})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if want := []string{"e-1", "e-2", "e-3"}; !equal(ids(rows), want) {
		t.Errorf("the read answers %v, want %v", ids(rows), want)
	}
}
