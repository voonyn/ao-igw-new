package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// grantOperator is the person every grant test acts as.
var grantOperator = GrantActor{TenantID: grantTenantID, UserID: grantUserID}

func testGrantService(t *testing.T, roles []string, rows []GrantRecord) *GrantService {
	t.Helper()
	log, _ := logger.NewObserved()

	return NewGrantService(GrantDeps{
		List: func(context.Context, string, GrantQuery) ([]GrantRecord, int64, error) {
			return rows, int64(len(rows)), nil
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) {
			return roles, nil
		},
		Log: log,
	})
}

// TestListGrantsRefusesAnybodyButATenantManager covers the gate. A grant reaches
// every organization, so only a tenant manager reads one.
func TestListGrantsRefusesAnybodyButATenantManager(t *testing.T) {
	svc := testGrantService(t, []string{"ORG_OWNER"}, nil)

	if _, _, err := svc.List(context.Background(), grantOperator, GrantQuery{Limit: 20}); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner reads %v, want ErrForbidden", err)
	}

	svc = testGrantService(t, []string{tenant.RoleIAMAdmin}, nil)
	if _, _, err := svc.List(context.Background(), grantOperator, GrantQuery{Limit: 20}); err != nil {
		t.Errorf("a tenant administrator reads %v, want the page", err)
	}
}

// TestListGrantsNamesTheKind covers what the console renders in the kind column.
// The kind is derived from the columns, so no page opens a sealed grant.
func TestListGrantsNamesTheKind(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	svc := testGrantService(t, []string{tenant.RoleIAMOwner}, []GrantRecord{
		{ID: codeGrantID, ClientID: grantClientID, AppName: "The Console",
			Subject: grantUserID, SubjectName: "The Owner",
			LoginSessionID: grantSessions, CreatedAt: at, ExpiresAt: at.Add(time.Hour)},
		{ID: refreshGrantID, ClientID: grantClientID, Subject: grantUserID, HasRefreshToken: true},
		{ID: machineGrantID, ClientID: goneClientID},
	})

	views, total, err := svc.List(context.Background(), grantOperator, GrantQuery{Limit: 20})
	if err != nil {
		t.Fatalf("list the grants: %v", err)
	}
	if total != 3 || len(views) != 3 {
		t.Fatalf("the page holds %d of %d rows, want 3 of 3", len(views), total)
	}

	kinds := []string{views[0].Kind, views[1].Kind, views[2].Kind}
	want := []string{KindAuthorizationCode, KindRefreshToken, KindClientCredentials}
	for i, kind := range kinds {
		if kind != want[i] {
			t.Errorf("grant %d reads kind %q, want %q", i, kind, want[i])
		}
	}

	// The client identifier is what the row carries, and the application name is
	// what the join found. A client that is gone keeps its identifier.
	if views[0].AppID != grantClientID || views[0].AppName != "The Console" {
		t.Errorf("the first grant reads %q named %q, want the client and its application",
			views[0].AppID, views[0].AppName)
	}
	if views[2].AppID != goneClientID || views[2].AppName != "" {
		t.Errorf("the machine grant reads %q named %q, want the client id and no name",
			views[2].AppID, views[2].AppName)
	}
	if !views[0].Created.Equal(at) || !views[0].Expires.Equal(at.Add(time.Hour)) {
		t.Errorf("the first grant runs %s to %s, want the seeded window",
			views[0].Created, views[0].Expires)
	}
}
