package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

// IntrospectionAllowed reports whether the authenticated client can inspect the
// token it presented. The protocol engine authenticates the client first, so
// this decides authorization alone.
//
// Two rules hold. A public client is refused, because it holds no secret and
// anybody can impersonate it. A confidential client reads its own token only,
// because the answer names the person the token was issued for.
func IntrospectionAllowed(_ context.Context, client *goidc.Client, info goidc.TokenInfo) bool {
	if client.IsPublic() {
		return false
	}
	return info.ClientID == client.ID
}
