package audit

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	feedTenantID = "t-1"
	feedUserID   = "u-1"
)

// feedOperator is the person every test of the feed acts as.
var feedOperator = Actor{TenantID: feedTenantID, UserID: feedUserID}

// listedQueries is the narrowing each read handed the repository.
var listedQueries []Query

// testService builds the feed service over the rows the repository answers, for
// a caller who does or does not administer the tenant.
func testService(t *testing.T, manager bool, rows []Event) *Service {
	t.Helper()
	log, _ := logger.NewObserved()
	listedQueries = nil

	return NewService(Deps{
		List: func(_ context.Context, _ string, q Query) ([]Event, int64, error) {
			listedQueries = append(listedQueries, q)
			return rows, int64(len(rows)), nil
		},
		TenantManager: func(context.Context, string, string) (bool, error) { return manager, nil },
		Log:           log,
	})
}

// TestListRefusesAPersonWhoDoesNotAdministerTheTenant covers the gate. The feed
// carries every organization of the tenant, so only a tenant manager reads it.
func TestListRefusesAPersonWhoDoesNotAdministerTheTenant(t *testing.T) {
	svc := testService(t, false, nil)

	if _, _, err := svc.List(context.Background(), feedOperator, Query{Limit: 20}); !errors.Is(err, ErrForbidden) {
		t.Errorf("a person with no tenant role reads %v, want ErrForbidden", err)
	}
	if len(listedQueries) != 0 {
		t.Errorf("the refused read reached the repository %d times, want 0", len(listedQueries))
	}
}

// TestListAnswersTheFeedToATenantManager covers the read one page answers, and
// the total the pager needs.
func TestListAnswersTheFeedToATenantManager(t *testing.T) {
	at := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	svc := testService(t, true, []Event{{
		ID:         "e-1",
		TenantID:   feedTenantID,
		ActorID:    "u-9",
		Action:     string(ActionOrgCreated),
		EntityType: EntityOrganization,
		EntityID:   "o-1",
		Result:     ResultSuccess,
		IP:         "203.0.113.7",
		UserAgent:  "a-browser",
		Metadata:   `{"org_id":"o-1"}`,
		CreatedAt:  at,
	}})

	views, total, err := svc.List(context.Background(), feedOperator, Query{Limit: 20})
	if err != nil {
		t.Fatalf("read the feed: %v", err)
	}
	if total != 1 || len(views) != 1 {
		t.Fatalf("the read answers %d rows and total %d, want 1 and 1", len(views), total)
	}

	want := EventView{
		ID:         "e-1",
		Actor:      "u-9",
		Action:     string(ActionOrgCreated),
		EntityType: EntityOrganization,
		EntityID:   "o-1",
		Result:     ResultSuccess,
		IP:         "203.0.113.7",
		UserAgent:  "a-browser",
		Metadata:   json.RawMessage(`{"org_id":"o-1"}`),
		CreatedAt:  at,
	}
	if !reflect.DeepEqual(views[0], want) {
		t.Errorf("the view reads %+v, want %+v", views[0], want)
	}
}

// TestListAnswersNoMetadataWhenTheRowHoldsNone covers the empty column. The
// console reads the field as JSON, and an empty string is not JSON.
func TestListAnswersNoMetadataWhenTheRowHoldsNone(t *testing.T) {
	svc := testService(t, true, []Event{{
		ID: "e-1", TenantID: feedTenantID, Action: string(ActionLoginFailed),
		EntityType: EntityUser, Result: ResultFailure,
	}})

	views, _, err := svc.List(context.Background(), feedOperator, Query{Limit: 20})
	if err != nil {
		t.Fatalf("read the feed: %v", err)
	}
	if views[0].Metadata != nil {
		t.Errorf("a row with no metadata reads %q, want no field at all", views[0].Metadata)
	}
}
