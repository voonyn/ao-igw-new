package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
)

// seedClientRow builds the row bootstrap writes for a first-party browser SPA:
// public client, no secret, S256 PKCE enforced by the provider config.
func seedClientRow() Client {
	return Client{
		AppID:                  "app-1",
		TenantID:               "tenant-1",
		ClientID:               "client-1",
		Name:                   "Console",
		CreatedAt:              time.Unix(1700000000, 0),
		TokenAuthnMethod:       "none",
		SubjectType:            "public",
		Scopes:                 "openid profile email offline_access",
		RedirectURIs:           []string{"https://console.example.com/callback"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		ResponseTypes:          []string{"code"},
		PostLogoutRedirectURIs: []string{"https://console.example.com/"},
		IsFirstParty:           true,
	}
}

// TestToGoidcClient covers the seeded first-party client: the protocol identity
// the engine reads comes from the row, and nothing else.
func TestToGoidcClient(t *testing.T) {
	client, err := toGoidcClient(seedClientRow())
	if err != nil {
		t.Fatalf("map client row: %v", err)
	}

	if client.ID != "client-1" {
		t.Errorf("client id is %q, want %q", client.ID, "client-1")
	}
	if client.Name != "Console" {
		t.Errorf("client name is %q, want %q", client.Name, "Console")
	}
	if !client.IsPublic() {
		t.Errorf("authn method is %q, want a public client", client.TokenAuthnMethod)
	}
	if client.SubIdentifierType != goidc.SubIdentifierPublic {
		t.Errorf("subject type is %q, want %q", client.SubIdentifierType, goidc.SubIdentifierPublic)
	}
	if client.ScopeIDs != "openid profile email offline_access" {
		t.Errorf("scopes are %q, want the four seeded scopes", client.ScopeIDs)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://console.example.com/callback" {
		t.Errorf("redirect URIs are %v, want the seeded callback", client.RedirectURIs)
	}
	wantGrants := []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantRefreshToken}
	if len(client.GrantTypes) != len(wantGrants) {
		t.Fatalf("grant types are %v, want %v", client.GrantTypes, wantGrants)
	}
	for i, want := range wantGrants {
		if client.GrantTypes[i] != want {
			t.Errorf("grant type %d is %q, want %q", i, client.GrantTypes[i], want)
		}
	}
	if len(client.ResponseTypes) != 1 || client.ResponseTypes[0] != goidc.ResponseTypeCode {
		t.Errorf("response types are %v, want [code]", client.ResponseTypes)
	}
	if client.CreatedAt != 1700000000 {
		t.Errorf("created at is %d, want 1700000000", client.CreatedAt)
	}
}

// TestToGoidcClient_Pairwise covers the subject type this step does not
// implement. A pairwise row must fail loudly, never fall back to public, because
// a public subject leaks the same identifier to every client.
func TestToGoidcClient_Pairwise(t *testing.T) {
	row := seedClientRow()
	row.SubjectType = "pairwise"

	if _, err := toGoidcClient(row); !errors.Is(err, ErrPairwiseSubject) {
		t.Fatalf("error is %v, want ErrPairwiseSubject", err)
	}
}

// TestVerifyClientSecret covers the confidential client credential: the stored
// value is a bcrypt hash, so the right secret passes and a wrong one fails.
func TestVerifyClientSecret(t *testing.T) {
	hash, err := aocrypto.HashPassword("the-client-secret")
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}

	if err := VerifyClientSecret(context.Background(), hash, "the-client-secret"); err != nil {
		t.Errorf("the right secret failed: %v", err)
	}
	if err := VerifyClientSecret(context.Background(), hash, "another-secret"); err == nil {
		t.Error("a wrong secret passed")
	}
}

// TestVerifyClientSecret_NoSecret covers the public client: it stores no secret,
// so an empty presented value must never match an empty stored value.
func TestVerifyClientSecret_NoSecret(t *testing.T) {
	if err := VerifyClientSecret(context.Background(), "", ""); err == nil {
		t.Error("an empty secret passed against an empty stored value")
	}
}
