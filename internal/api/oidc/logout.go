package oidc

import (
	"context"
	"net/http"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/audit"
	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// logoutPolicyID names the logout policy in the logout session. The engine
// stores it before it runs the policy.
const logoutPolicyID = "login-session-logout"

// claimSessionID names the login session in the ID token and in the grant
// store. The storage repository extracts the grant column from the same key, so
// both sides read one constant.
const claimSessionID = aooidc.ClaimSessionID

// Terminator ends one login session of one tenant. It is a function value, so
// this package never imports the session package, which imports this one.
type Terminator func(ctx context.Context, tenantID, sessionID string) error

// GrantLister reads every grant one login session produced.
type GrantLister func(ctx context.Context, tenantID, sessionID string) ([]*goidc.Grant, error)

// GrantRevoker saves one revoked grant. The storage manager is what the policy
// receives, so each save records token.revoked by itself. See storage.go.
type GrantRevoker func(ctx context.Context, grant *goidc.Grant) error

// LogoutDeps is what the logout policy of one tenant calls. A nil recorder
// leaves the logout unrecorded, which matches the token handler in provider.go.
type LogoutDeps struct {
	Terminate Terminator
	Grants    GrantLister
	Revoke    GrantRevoker
	Audit     *audit.Recorder
	Log       logger.Logger
}

// LogoutPolicy ends the login session an RP-initiated logout names. The
// provider is built per tenant, so the tenant is bound here.
func LogoutPolicy(tenantID string, deps LogoutDeps) goidc.LogoutPolicy {
	return goidc.NewLogoutPolicy(logoutPolicyID,
		func(*http.Request, *goidc.LogoutSession) bool { return true },
		func(_ http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
			// The hint is what names the login session. goidc accepts a logout
			// request without one, and such a request says nothing about who is
			// signing out, so it is refused here.
			if ls.IDTokenHintClaims == nil {
				deps.Log.Warn("logout request without an id_token_hint",
					logger.String("tenant_id", tenantID),
					logger.String("client_id", ls.ClientID))
				return goidc.StatusFailure,
					goidc.NewError(goidc.ErrorCodeInvalidRequest, "id_token_hint is required")
			}

			sessionID, _ := ls.IDTokenHintClaims.AdditionalClaims[claimSessionID].(string)
			if sessionID == "" {
				deps.Log.Warn("logout request whose id_token_hint carries no sid claim",
					logger.String("tenant_id", tenantID),
					logger.String("client_id", ls.ClientID))
				return goidc.StatusFailure,
					goidc.NewError(goidc.ErrorCodeInvalidRequest, "id_token_hint carries no sid claim")
			}

			deps.Log.Debug("end the login session",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", sessionID),
				logger.String("client_id", ls.ClientID))

			if err := deps.Terminate(r.Context(), tenantID, sessionID); err != nil {
				return goidc.StatusFailure, err
			}

			if err := deps.revoke(r.Context(), tenantID, sessionID); err != nil {
				deps.Log.Error("revoke the grants of the login session",
					logger.String("tenant_id", tenantID),
					logger.String("session_id", sessionID),
					logger.Err(err))
				return goidc.StatusFailure, err
			}

			if err := deps.record(r, tenantID, sessionID, ls); err != nil {
				return goidc.StatusFailure, err
			}
			return goidc.StatusSuccess, nil
		})
}

// DefaultPostLogout is where the browser lands when the logout request names no
// post_logout_redirect_uri. The person signed out of every application of the
// tenant, so the login UI is the only page left to show.
//
// A registered post_logout_redirect_uri never reaches this, because goidc
// redirects to it and calls this only when the parameter is absent.
func DefaultPostLogout(loginURL string, log logger.Logger) goidc.HandleDefaultPostLogoutFunc {
	return func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) error {
		log.Debug("send the signed-out browser to the login UI",
			logger.String("client_id", ls.ClientID))

		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return nil
	}
}

// revoke ends every grant the login session produced.
//
// A refresh token dies with its grant, so no application of the tenant can mint
// a new token after the sign-out. An access token already issued is a JWT that
// no store holds, and it stays valid until it expires.
//
// A grant that is already revoked is left alone. Saving it again would record a
// second token.revoked row for one revocation.
func (deps LogoutDeps) revoke(ctx context.Context, tenantID, sessionID string) error {
	grants, err := deps.Grants(ctx, tenantID, sessionID)
	if err != nil {
		return err
	}

	now := int(time.Now().UTC().Unix())
	for _, grant := range grants {
		if grant.RevokedAt != 0 {
			continue
		}
		grant.RevokedAt = now
		if err := deps.Revoke(ctx, grant); err != nil {
			return err
		}
	}
	return nil
}

// record writes the audit row of one logout. The row names the person, the
// login session, and the client that asked for the logout.
//
// A failed write fails the logout, because a sign-out nobody can audit is not
// allowed to stand. The engine calls the policy before it redirects, so a
// refusal here means the browser never reaches the client.
//
// ponytail: the row carries no IP. The engine hands this handler a net/http
// request, and the peer address of that request is the proxy rather than the
// person. Thread the resolved address through the request context when a report
// asks for it.
func (deps LogoutDeps) record(
	r *http.Request, tenantID, sessionID string, ls *goidc.LogoutSession,
) error {
	if deps.Audit == nil {
		return nil
	}
	return deps.Audit.Record(r.Context(), audit.Entry{
		TenantID:   tenantID,
		ActorID:    ls.IDTokenHintClaims.Subject,
		Action:     audit.ActionLogoutSucceeded,
		EntityType: audit.EntitySession,
		EntityID:   sessionID,
		UserAgent:  r.UserAgent(),
		Metadata:   map[string]any{"client_id": ls.ClientID},
	})
}
