package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
)

// accountQueries is the narrowing each read handed the repository.
var accountQueries []Query

// testAccountService builds the activity feed over the rows the repository
// answers. The repository is a closure, so the logic is covered without a
// database.
func testAccountService(t *testing.T, rows []Event, fail error) *AccountService {
	t.Helper()
	log, _ := logger.NewObserved()
	accountQueries = nil

	return NewAccountService(AccountDeps{
		List: func(_ context.Context, _ string, q Query) ([]Event, int64, error) {
			accountQueries = append(accountQueries, q)
			if fail != nil {
				return nil, 0, fail
			}
			return rows, int64(len(rows)) + 40, nil
		},
		Log: log,
	})
}

// TestAccountListReadsOnlyTheEventsTheCallerCaused covers the actor filter. The
// read must name the caller, so the feed is about that person and about nobody
// else.
func TestAccountListReadsOnlyTheEventsTheCallerCaused(t *testing.T) {
	svc := testAccountService(t, nil, nil)

	if _, _, err := svc.List(context.Background(), feedOperator, Query{Limit: 20}); err != nil {
		t.Fatalf("the feed answered %v, want no error", err)
	}
	if len(accountQueries) != 1 {
		t.Fatalf("the read reached the repository %d times, want 1", len(accountQueries))
	}
	if got := accountQueries[0].Actor; got != feedUserID {
		t.Errorf("the read named actor %q, want %q", got, feedUserID)
	}
}

// TestAccountListOverwritesAnActorTheRequestNamed covers the one rule of this
// service. A request that names another person reads its own feed, so no event
// of another person is reachable.
func TestAccountListOverwritesAnActorTheRequestNamed(t *testing.T) {
	svc := testAccountService(t, nil, nil)

	q := Query{Actor: "u-someone-else", Limit: 20}
	if _, _, err := svc.List(context.Background(), feedOperator, q); err != nil {
		t.Fatalf("the feed answered %v, want no error", err)
	}
	if got := accountQueries[0].Actor; got != feedUserID {
		t.Errorf("the read named actor %q, want the caller %q", got, feedUserID)
	}
}

// TestAccountListWithholdsTheOperatorFields covers what the answer carries. The
// actor and the metadata of the row are operator-facing, and neither is copied
// onto the view at all.
func TestAccountListWithholdsTheOperatorFields(t *testing.T) {
	at := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	svc := testAccountService(t, []Event{{
		ID:         "e-1",
		TenantID:   feedTenantID,
		ActorID:    feedUserID,
		Action:     string(ActionPasswordChanged),
		EntityType: EntityUser,
		EntityID:   feedUserID,
		Result:     ResultSuccess,
		IP:         "203.0.113.7",
		UserAgent:  "a-browser",
		Metadata:   `{"org_id":"o-1"}`,
		CreatedAt:  at,
	}}, nil)

	views, total, err := svc.List(context.Background(), feedOperator, Query{Limit: 20})
	if err != nil {
		t.Fatalf("the feed answered %v, want no error", err)
	}
	if len(views) != 1 {
		t.Fatalf("the feed answered %d rows, want 1", len(views))
	}

	want := ActivityView{
		ID:         "e-1",
		Action:     string(ActionPasswordChanged),
		EntityType: EntityUser,
		EntityID:   feedUserID,
		Result:     ResultSuccess,
		IP:         "203.0.113.7",
		UserAgent:  "a-browser",
		CreatedAt:  at,
	}
	if views[0] != want {
		t.Errorf("the feed answered %+v, want %+v", views[0], want)
	}

	// The total counts the whole match and not the page, because the portal
	// renders its pager from it.
	if total != 41 {
		t.Errorf("the feed answered a total of %d, want 41", total)
	}
}

// TestAccountListKeepsTheWindowTheRequestAsked covers the paging. The offset and
// the limit reach the repository unchanged, so page two reads page two.
func TestAccountListKeepsTheWindowTheRequestAsked(t *testing.T) {
	svc := testAccountService(t, nil, nil)

	if _, _, err := svc.List(context.Background(), feedOperator, Query{Limit: 50, Offset: 50}); err != nil {
		t.Fatalf("the feed answered %v, want no error", err)
	}
	if got := accountQueries[0]; got.Limit != 50 || got.Offset != 50 {
		t.Errorf("the read asked for limit %d offset %d, want 50 and 50", got.Limit, got.Offset)
	}
}

// TestAccountListReportsAFailedRead covers the error path. The read failure
// travels up unchanged, so the mapper answers a server error.
func TestAccountListReportsAFailedRead(t *testing.T) {
	broken := errors.New("the database is down")
	svc := testAccountService(t, nil, broken)

	if _, _, err := svc.List(context.Background(), feedOperator, Query{Limit: 20}); !errors.Is(err, broken) {
		t.Errorf("the feed answered %v, want the read failure", err)
	}
}
