package oidc

import (
	"context"
	"maps"
	"strconv"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"

	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ClaimsFinder reads the claims of one person for the scopes the grant holds.
type ClaimsFinder func(ctx context.Context, tenantID, userID string, scopes []string) (aooidc.Claims, error)

// IDTokenClaims is the goidc side of the ID token claims. The provider is built
// per tenant, so the tenant is bound here and the grant names the person.
// The ID token also carries the four claims that describe the sign-in itself.
// See withSignInClaims below, and signInClaims in policy.go, which writes them.
func IDTokenClaims(tenantID string, find ClaimsFinder, log logger.Logger) goidc.IDTokenClaimsFunc {
	return func(ctx context.Context, grant *goidc.Grant) map[string]any {
		return withSignInClaims(grantClaims(ctx, tenantID, grant, find, log).IDToken, grant, log)
	}
}

// withSignInClaims adds what the ID token publishes about the sign-in: the login
// session, the factors the person proved, the assurance level of the sign-in,
// and the moment they last proved a factor.
//
// sid names the login session the grant was authorized on. An RP-initiated
// logout reads it back off the id_token_hint to know which session to end. See
// logout.go.
//
// Each value comes off the grant store, where the finalize step wrote it at
// authorization. Nothing is read again here, so a refreshed ID token reports the
// sign-in that happened and never the account as it stands now. See
// signInClaims in policy.go and docs/adr/0010.
//
// A claim mapper cannot overwrite any of the four. The mapper API refuses every
// one of these names. See internal/oidc/mapper_admin_service.go.
func withSignInClaims(claims map[string]any, grant *goidc.Grant, log logger.Logger) map[string]any {
	store := grant.Store
	published := make(map[string]any, 4)

	if sessionID, _ := store[claimSessionID].(string); sessionID != "" {
		published[claimSessionID] = sessionID
	}
	// The store encodes the factor list as one delimited string, so it is split
	// back into the array the claim publishes.
	if methods, _ := store[goidc.ClaimAMR].(string); methods != "" {
		published[goidc.ClaimAMR] = strings.Fields(methods)
	}
	if level, _ := store[goidc.ClaimACR].(string); level != "" {
		published[goidc.ClaimACR] = level
	}
	// The finalize step wrote whole seconds, so a value that does not parse is a
	// corrupted store. The claim is dropped rather than published as text, and
	// the failure is logged here, where it stops.
	if at, _ := store[goidc.ClaimAuthTime].(string); at != "" {
		secs, err := strconv.ParseInt(at, 10, 64)
		if err != nil {
			log.Error("read auth_time off the grant",
				logger.String("grant_id", grant.ID),
				logger.String("user_id", grant.Subject),
				logger.Err(err))
		} else {
			published[goidc.ClaimAuthTime] = secs
		}
	}

	if len(published) == 0 {
		return claims
	}
	if claims == nil {
		claims = make(map[string]any, len(published))
	}
	maps.Copy(claims, published)
	return claims
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
