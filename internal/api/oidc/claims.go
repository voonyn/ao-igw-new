package oidc

import (
	"context"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"

	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ClaimsFinder reads the claims of one person for the scopes the grant holds.
type ClaimsFinder func(ctx context.Context, tenantID, userID string, scopes []string) (aooidc.Claims, error)

// IDTokenClaims is the goidc side of the ID token claims. The provider is built
// per tenant, so the tenant is bound here and the grant names the person.
// The ID token also carries the sid claim, which names the login session the
// grant was authorized on. An RP-initiated logout reads it back off the
// id_token_hint to know which session to end. See logout.go.
func IDTokenClaims(tenantID string, find ClaimsFinder, log logger.Logger) goidc.IDTokenClaimsFunc {
	return func(ctx context.Context, grant *goidc.Grant) map[string]any {
		claims := grantClaims(ctx, tenantID, grant, find, log).IDToken

		sessionID, _ := grant.Store[claimSessionID].(string)
		if sessionID == "" {
			return claims
		}
		if claims == nil {
			claims = make(map[string]any, 1)
		}
		claims[claimSessionID] = sessionID
		return claims
	}
}

// UserInfoClaims is the goidc side of the userinfo claims. The access token
// names the grant, and the grant names the person and the granted scopes.
func UserInfoClaims(tenantID string, find ClaimsFinder, log logger.Logger) goidc.UserInfoClaimsFunc {
	return func(ctx context.Context, grant *goidc.Grant) map[string]any {
		return grantClaims(ctx, tenantID, grant, find, log).UserInfo
	}
}

// grantClaims reads the claims of the person the grant names.
//
// goidc takes no error here, so a failed read releases nothing. The error is
// logged once, and the token or the userinfo answer carries the standard claims
// alone.
func grantClaims(
	ctx context.Context, tenantID string, grant *goidc.Grant,
	find ClaimsFinder, log logger.Logger,
) aooidc.Claims {
	claims, err := find(ctx, tenantID, grant.Subject, strings.Fields(grant.Scopes))
	if err != nil {
		log.Error("read claims",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", grant.Subject),
			logger.Err(err))
		return aooidc.Claims{}
	}
	return claims
}
