package oidc

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

// introspectClient is the client that calls the introspection endpoint. The
// authentication method states whether the client is confidential.
func introspectClient(id string, authn goidc.AuthnMethod) *goidc.Client {
	return &goidc.Client{
		ID:         id,
		ClientMeta: goidc.ClientMeta{TokenAuthnMethod: authn},
	}
}

// TestIntrospectionAllowed covers who can inspect a token. A confidential
// client reads its own token. A public client reads nothing, because it holds
// no secret. A confidential client reads no token of another client.
func TestIntrospectionAllowed(t *testing.T) {
	cases := []struct {
		name   string
		client *goidc.Client
		info   goidc.TokenInfo
		want   bool
	}{
		{
			name:   "confidential client and its own token",
			client: introspectClient("client-1", goidc.AuthnMethodSecretBasic),
			info:   goidc.TokenInfo{ClientID: "client-1"},
			want:   true,
		},
		{
			name:   "public client",
			client: introspectClient("client-1", goidc.AuthnMethodNone),
			info:   goidc.TokenInfo{ClientID: "client-1"},
			want:   false,
		},
		{
			name:   "confidential client and the token of another client",
			client: introspectClient("client-1", goidc.AuthnMethodSecretBasic),
			info:   goidc.TokenInfo{ClientID: "client-2"},
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IntrospectionAllowed(context.Background(), tc.client, tc.info)
			if got != tc.want {
				t.Errorf("IntrospectionAllowed gives %t, want %t", got, tc.want)
			}
		})
	}
}
