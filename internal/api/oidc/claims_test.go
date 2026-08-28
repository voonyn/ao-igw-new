package oidc

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"go.uber.org/zap/zapcore"

	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// claimsOf stands in for the claims service, which needs a database. It records
// what the adapter asked for, and answers with fixed claims.
type claimsOf struct {
	tenantID string
	userID   string
	scopes   []string
	claims   aooidc.Claims
	err      error
}

func (c *claimsOf) find(_ context.Context, tenantID, userID string, scopes []string) (aooidc.Claims, error) {
	c.tenantID, c.userID, c.scopes = tenantID, userID, scopes
	return c.claims, c.err
}

// TestIDTokenClaimsAdapter covers the goidc side of the ID token claims. The
// adapter reads the subject and the granted scopes of the grant, binds the
// tenant the provider was built for, and releases the ID token half alone.
func TestIDTokenClaimsAdapter(t *testing.T) {
	log, _ := logger.NewObserved()
	source := &claimsOf{claims: aooidc.Claims{
		IDToken:  map[string]any{"given_name": "Ada"},
		UserInfo: map[string]any{"email": "person@example.com"},
	}}

	got := IDTokenClaims("tenant-1", source.find, log)(
		context.Background(),
		&goidc.Grant{Subject: "user-1", Scopes: "openid profile email"})

	want := map[string]any{"given_name": "Ada"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the ID token carries %v, want %v", got, want)
	}
	if source.tenantID != "tenant-1" || source.userID != "user-1" {
		t.Errorf("the adapter asked for tenant %q and user %q, want tenant-1 and user-1",
			source.tenantID, source.userID)
	}
	wantScopes := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(source.scopes, wantScopes) {
		t.Errorf("the adapter asked for scopes %v, want %v", source.scopes, wantScopes)
	}
}

// TestIDTokenCarriesTheSessionID covers the sid claim. The grant carries the
// login session it was authorized on, and the ID token publishes it, so an
// RP-initiated logout can name the session to end.
func TestIDTokenCarriesTheSessionID(t *testing.T) {
	log, _ := logger.NewObserved()
	source := &claimsOf{claims: aooidc.Claims{IDToken: map[string]any{"given_name": "Ada"}}}

	got := IDTokenClaims("tenant-1", source.find, log)(
		context.Background(),
		&goidc.Grant{
			Subject: "user-1",
			Scopes:  "openid profile",
			Store:   map[string]any{"sid": "session-1"},
		})

	want := map[string]any{"given_name": "Ada", "sid": "session-1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the ID token carries %v, want %v", got, want)
	}
}

// TestUserInfoClaimsAdapter covers the goidc side of the userinfo claims. The
// userinfo answer carries the userinfo half alone.
func TestUserInfoClaimsAdapter(t *testing.T) {
	log, _ := logger.NewObserved()
	source := &claimsOf{claims: aooidc.Claims{
		IDToken:  map[string]any{"given_name": "Ada"},
		UserInfo: map[string]any{"email": "person@example.com"},
	}}

	got := UserInfoClaims("tenant-1", source.find, log)(
		context.Background(),
		&goidc.Grant{Subject: "user-1", Scopes: "openid email"})

	want := map[string]any{"email": "person@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("userinfo carries %v, want %v", got, want)
	}
}

// TestClaimsAdapterReadFails covers a claim source the gateway cannot read.
// goidc takes no error here, so the answer carries no extra claim, and the
// failure is logged once.
func TestClaimsAdapterReadFails(t *testing.T) {
	log, logs := logger.NewObserved()
	source := &claimsOf{err: errors.New("database is down")}

	if got := IDTokenClaims("tenant-1", source.find, log)(
		context.Background(), &goidc.Grant{Subject: "user-1"}); len(got) != 0 {
		t.Errorf("the ID token carries %v, want nothing", got)
	}
	if got := UserInfoClaims("tenant-1", source.find, log)(
		context.Background(), &goidc.Grant{Subject: "user-1"}); len(got) != 0 {
		t.Errorf("userinfo carries %v, want nothing", got)
	}
	if entries := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); entries != 2 {
		t.Errorf("the failed read logged %d errors, want 2", entries)
	}
}

// TestIDTokenCarriesHowThePersonAuthenticated covers amr, acr and auth_time.
// The finalize step wrote all three onto the grant store as strings, and the
// claim builder answers amr as an array and auth_time as a number.
func TestIDTokenCarriesHowThePersonAuthenticated(t *testing.T) {
	log, _ := logger.NewObserved()
	source := &claimsOf{claims: aooidc.Claims{IDToken: map[string]any{"given_name": "Ada"}}}

	got := IDTokenClaims("tenant-1", source.find, log)(
		context.Background(),
		&goidc.Grant{
			Subject: "user-1",
			Scopes:  "openid profile",
			Store: map[string]any{
				"sid":       "session-1",
				"amr":       "otp pwd mfa",
				"acr":       testACRPrefix + ":2fa",
				"auth_time": "1756339200",
			},
		})

	want := map[string]any{
		"given_name": "Ada",
		"sid":        "session-1",
		"amr":        []string{"otp", "pwd", "mfa"},
		"acr":        testACRPrefix + ":2fa",
		"auth_time":  int64(1756339200),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the ID token carries %v, want %v", got, want)
	}
}

// TestIDTokenCarriesNoSignInClaimsWithoutAStore covers a grant that describes no
// sign-in, which is what the client credentials of a machine leave behind. The
// ID token then carries the standard claims alone.
func TestIDTokenCarriesNoSignInClaimsWithoutAStore(t *testing.T) {
	log, _ := logger.NewObserved()
	source := &claimsOf{claims: aooidc.Claims{IDToken: map[string]any{"given_name": "Ada"}}}

	got := IDTokenClaims("tenant-1", source.find, log)(
		context.Background(), &goidc.Grant{Subject: "user-1", Scopes: "openid"})

	if want := map[string]any{"given_name": "Ada"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the ID token carries %v, want %v", got, want)
	}
}

// TestIDTokenDropsACorruptedAuthTime covers a store the finalize step could not
// have written. The claim is dropped rather than published as text, the other
// claims still reach the token, and the failure is logged once.
func TestIDTokenDropsACorruptedAuthTime(t *testing.T) {
	log, logs := logger.NewObserved()
	source := &claimsOf{}

	got := IDTokenClaims("tenant-1", source.find, log)(
		context.Background(),
		&goidc.Grant{
			ID:      "grant-1",
			Subject: "user-1",
			Store:   map[string]any{"acr": testACRPrefix + ":1fa", "auth_time": "yesterday"},
		})

	if _, held := got["auth_time"]; held {
		t.Errorf("the ID token carries auth_time %v, want nothing", got["auth_time"])
	}
	if want := testACRPrefix + ":1fa"; got["acr"] != want {
		t.Errorf("acr is %v, want %q", got["acr"], want)
	}
	if entries := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); entries != 1 {
		t.Errorf("the corrupted value logged %d errors, want 1", entries)
	}
}
