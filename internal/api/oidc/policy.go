package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/audit"
	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// policyID names the authentication policy in the authn session. The engine
// stores it on the first pass and reads it back on the resume pass.
const policyID = "login-handoff"

// storeErrorKey names the failure marker on the authn session. The login UI
// writes it when it cannot sign the person in without rendering a page, and the
// policy fails the request with the code it holds. See docs/adr/0004.
const storeErrorKey = "login_error"

// errorCodeConsentRequired is what a silent request that needs consent answers
// with. OpenID Connect Core defines the code, and goidc declares no constant
// for it.
const errorCodeConsentRequired = goidc.ErrorCode("consent_required")

// The suffixes of the two assurance levels this gateway measures: one factor,
// and two or more. Each is appended to the configured URN prefix.
//
// A level says how many factors, never which. A relying party that needs the
// names reads amr. See docs/adr/0010.
const (
	acrOneFactor   = "1fa"
	acrMultiFactor = "2fa"
)

// loginPath is the page the login UI starts every sign-in on.
const loginPath = "/identifier"

// authRequestParam carries the authn session id to the login UI and back.
const authRequestParam = "authRequest"

// authorizePath is where the protocol engine resumes a suspended authorization
// request. The engine reads the authn session id off the last segment.
const authorizePath = "/authorize/"

// ErrInteractionRequired reports an authorization request that the login UI
// cannot finish without the person. Either nobody is signed in, or the client
// asked for a new sign-in with prompt=login or with max_age.
var ErrInteractionRequired = errors.New("the authorization request needs the person")

// The sentinels this package answers with. A package registers its own, so no
// other one maps an error it does not declare.
//
// The login UI reads the 401 and renders the sign-in flow.
func init() {
	response.Map(ErrInteractionRequired, fiber.StatusUnauthorized, "interaction_required", "Unauthorized")
}

// LoginPolicy is the authentication policy of every tenant. It is blind: it
// never reads a login session and it never verifies a credential. It hands the
// browser to the login UI, and the login UI hands back a subject through
// Complete. See docs/adr/0004.
func LoginPolicy(loginURL string, log logger.Logger) goidc.AuthnPolicy {
	return goidc.NewPolicy(policyID,
		func(*http.Request, *goidc.AuthnSession, *goidc.Client) bool { return true },
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
			if code, ok := as.Store[storeErrorKey].(string); ok && code != "" {
				log.Warn("authorization request refused by the login UI",
					logger.String("session_id", as.ID),
					logger.String("client_id", as.ClientID),
					logger.String("error_code", code))
				return goidc.StatusFailure, goidc.NewError(goidc.ErrorCode(code), "the person did not sign in")
			}

			if as.Subject != "" {
				log.Debug("authorization request resumed",
					logger.String("session_id", as.ID), logger.String("client_id", as.ClientID))
				return goidc.StatusSuccess, nil
			}

			log.Debug("hand the authorization request to the login UI",
				logger.String("session_id", as.ID), logger.String("client_id", as.ClientID))
			http.Redirect(w, r, loginRedirect(loginURL, as.ID), http.StatusSeeOther)
			return goidc.StatusPending, nil
		})
}

// loginRedirect is where the browser signs in. The login UI reads the authn
// session id off the query and carries it through every step.
func loginRedirect(loginURL, id string) string {
	return fmt.Sprintf("%s%s?%s=%s", loginURL, loginPath, authRequestParam, url.QueryEscape(id))
}

// Completion is what the login UI knows when it finalizes one authorization
// request: which request, who signed in, and what the person answered on the
// consent screen.
//
// Subject is empty when nobody is signed in. AuthTime is the moment the person
// verified a factor, which prompt=login and max_age are measured against.
// Consent is nil until the person answers the screen.
// SessionID is the login session the person signed in on. It travels to the
// grant and out as the sid claim of the ID token, so a later logout can name
// the session to end.
// Factors names every factor the person proved on that session, in a stable
// order. It travels the same way and leaves as the amr claim.
type Completion struct {
	TenantID      string
	Issuer        string
	AuthRequestID string
	Subject       string
	SessionID     string
	Factors       []string
	AuthTime      time.Time
	Consent       *bool
	IP            string
	UserAgent     string
}

// Outcome is what the login UI does next: send the browser to RedirectTo, or
// render the consent screen for ClientID and Scopes.
type Outcome struct {
	RedirectTo      string
	ConsentRequired bool
	ClientID        string
	Scopes          []string
}

// Completer finalizes one authorization request. It serves both the finalize
// step and the consent step, which differ only in the Consent field.
//
// It returns ErrInteractionRequired when the request needs the person, and
// aooidc.ErrSessionNotFound when no request carries the id.
type Completer func(ctx context.Context, done Completion) (Outcome, error)

// Consenter reports the scopes the person must still approve. An empty answer
// means the request needs no consent screen.
type Consenter func(ctx context.Context, tenantID, userID, clientID string, requested []string, force bool) ([]string, error)

// ConsentWriter records one answer the person gave on the consent screen.
type ConsentWriter func(ctx context.Context, given aooidc.Consent) error

// CompleterDeps is what the finalize step reads and writes.
type CompleterDeps struct {
	PathPrefix string

	// ACRPrefix is the URN the two assurance levels are built on. The provider
	// advertises the same two values, so both read one deployment setting.
	ACRPrefix string

	Find       SessionFinder
	Save       SessionSaver
	Decide     Consenter
	Approve    ConsentWriter
	Deny       ConsentWriter
	Log        logger.Logger
}

// NewCompleter returns the Completer the login handler calls. It is the only
// writer of the subject and the granted scopes on an authn session.
func NewCompleter(deps CompleterDeps) Completer {
	pathPrefix, find, save, log := deps.PathPrefix, deps.Find, deps.Save, deps.Log

	return func(ctx context.Context, done Completion) (Outcome, error) {
		log.Debug("complete authorization request",
			logger.String("tenant_id", done.TenantID),
			logger.String("session_id", done.AuthRequestID))

		as, err := find(ctx, done.TenantID, done.AuthRequestID)
		if err != nil {
			if !errors.Is(err, aooidc.ErrSessionNotFound) {
				log.Error("read authn session",
					logger.String("tenant_id", done.TenantID),
					logger.String("session_id", done.AuthRequestID),
					logger.Err(err))
			}
			return Outcome{}, err
		}

		if reason := interaction(as, done); reason != "" {
			// A silent request must never reach a rendered page, so the marker
			// carries the refusal back through the engine instead.
			if as.Prompt != goidc.PromptTypeNone {
				return Outcome{}, fmt.Errorf("%w: %s", ErrInteractionRequired, reason)
			}
			mark(as, goidc.ErrorCodeLoginRequired)
		} else if asked, refused, err := deps.consent(ctx, as, done); err != nil {
			return Outcome{}, err
		} else if len(asked) > 0 && as.Prompt == goidc.PromptTypeNone {
			// A silent request must never reach a rendered page, so the marker
			// carries the refusal back through the engine instead.
			mark(as, errorCodeConsentRequired)
		} else if len(asked) > 0 {
			// The screen renders next, so the session keeps no subject yet. A
			// person who abandons the screen grants nothing.
			return Outcome{ConsentRequired: true, ClientID: as.ClientID, Scopes: asked}, nil
		} else if refused {
			mark(as, goidc.ErrorCodeAccessDenied)
		} else {
			as.Subject = done.Subject
			// goidc copies this store onto the grant, and IDTokenClaims reads
			// the sid back off it. It is the only carrier from here to the
			// token endpoint, where the ID token is minted.
			remember(as, claimSessionID, done.SessionID)
			signInClaims(as, done, deps.ACRPrefix)
			// A marker from an earlier silent pass must not outlive the sign-in
			// that follows it. The policy reads the marker before the subject,
			// so a marker left behind fails the request forever.
			delete(as.Store, storeErrorKey)
			// Consent is all-or-nothing, so a granted request receives what it
			// asked for and never the wider set the person approved before.
			as.GrantedScopes = as.Scopes
			// The same for the resource the client named (RFC 8707). The engine
			// validates the value against the tenant list and stores it, and it
			// grants nothing by itself: the token endpoint reads the granted set,
			// so a resource left ungranted here is refused as an invalid target.
			as.GrantedResources = as.Resources
		}

		if err := save(ctx, done.TenantID, as); err != nil {
			log.Error("save authn session",
				logger.String("tenant_id", done.TenantID),
				logger.String("session_id", as.ID),
				logger.Err(err))
			return Outcome{}, err
		}

		log.Debug("completed authorization request",
			logger.String("tenant_id", done.TenantID),
			logger.String("session_id", as.ID),
			logger.String("client_id", as.ClientID))
		return Outcome{RedirectTo: done.Issuer + pathPrefix + authorizePath + as.ID}, nil
	}
}

// mark writes the failure marker the policy reads. The browser then returns to
// the engine, which answers the client with the code.
func mark(as *goidc.AuthnSession, code goidc.ErrorCode) {
	remember(as, storeErrorKey, string(code))
}

// remember writes one value onto the store of the authn session. An empty value
// writes nothing, so the store never carries a key that names nothing.
func remember(as *goidc.AuthnSession, key, value string) {
	if value == "" {
		return
	}
	if as.Store == nil {
		as.Store = make(map[string]any, 1)
	}
	as.Store[key] = value
}

// signInClaims writes what the ID token publishes about this sign-in onto the
// store of the authn session: the factors the person proved, the assurance
// level of the sign-in, and the moment they last proved a factor.
//
// goidc copies the store onto the grant, and IDTokenClaims reads the three back
// when a token is minted. Writing them here freezes them at the sign-in event,
// which is the point: amr states what happened at one sign-in, so a refreshed ID
// token reports the original factors even after the person removes one. It is
// deliberate, and not a stale read. See docs/adr/0010.
//
// The store round-trips through JSON, so a []string would come back as a []any.
// Each value is written as one string, the way scope already encodes a list, and
// the claim builder splits it back into an array.
func signInClaims(as *goidc.AuthnSession, done Completion, acrPrefix string) {
	if len(done.Factors) == 0 {
		return
	}
	remember(as, goidc.ClaimAMR, strings.Join(amr(done.Factors), " "))
	remember(as, goidc.ClaimACR, acrValue(acrPrefix, acrLevel(len(done.Factors))))
	remember(as, goidc.ClaimAuthTime, strconv.FormatInt(done.AuthTime.Unix(), 10))
}

// amr is what the person proved, as the ID token names it: every factor of the
// login session, and mfa as well when they proved two or more.
func amr(factors []string) []string {
	if len(factors) < 2 {
		return factors
	}
	return append(slices.Clone(factors), string(goidc.AMRMultipleFactor))
}

// acrValue is one assurance level as the acr claim publishes it, under the URN
// prefix the deployment configured. The provider advertises exactly the values
// this builds.
func acrValue(prefix, level string) string {
	return prefix + ":" + level
}

// acrLevel is the assurance level a sign-in that proved this many factors
// reached. It says how many factors, never which.
func acrLevel(factors int) string {
	if factors < 2 {
		return acrOneFactor
	}
	return acrMultiFactor
}

// consent runs the consent gate of one authorization request.
//
// asked names the scopes the screen must ask for. refused reports that the
// person answered no. Both empty and false mean the request grants now.
func (deps CompleterDeps) consent(
	ctx context.Context, as *goidc.AuthnSession, done Completion,
) (asked []string, refused bool, err error) {
	requested := strings.Fields(as.Scopes)
	force := as.Prompt == goidc.PromptTypeConsent

	asked, err = deps.Decide(ctx, done.TenantID, done.Subject, as.ClientID, requested, force)
	if err != nil {
		deps.Log.Error("decide consent",
			logger.String("tenant_id", done.TenantID),
			logger.String("session_id", as.ID),
			logger.String("client_id", as.ClientID),
			logger.Err(err))
		return nil, false, err
	}
	if len(asked) == 0 {
		return nil, false, nil
	}

	given := aooidc.Consent{
		TenantID:  done.TenantID,
		UserID:    done.Subject,
		ClientID:  as.ClientID,
		Scopes:    asked,
		IP:        done.IP,
		UserAgent: done.UserAgent,
	}
	switch {
	case done.Consent == nil:
		return asked, false, nil
	case *done.Consent:
		return nil, false, deps.Approve(ctx, given)
	default:
		return nil, true, deps.Deny(ctx, given)
	}
}

// interaction reports why the request needs the person, and an empty string
// when it does not.
func interaction(as *goidc.AuthnSession, done Completion) string {
	if done.Subject == "" {
		return "nobody is signed in"
	}
	if as.Prompt == goidc.PromptTypeLogin && done.AuthTime.Unix() < int64(as.CreatedAt) {
		return "prompt=login demands a new sign-in"
	}
	if as.MaxAuthnAgeSecs != nil && time.Since(done.AuthTime) > time.Duration(*as.MaxAuthnAgeSecs)*time.Second {
		return "the sign-in is older than max_age"
	}
	return ""
}

// tokenAudit records every token the engine mints.
//
// The engine calls this from the token minting path, which the token endpoint
// serves. That endpoint mounts middlewares.InTx, so the write runs on the
// transaction the grant is saved on, and the row and the grant land together or
// not at all.
//
// The grant handler is deliberately not used for this. It runs from NewGrant,
// which for the authorization code grant runs at the authorization endpoint,
// when the code is minted rather than when a token is. A code that nobody
// exchanges would then leave a token.issued row behind.
//
// The row names the grant, the client, and the scopes the token carries. It
// never names the token, because the token is the credential.
//
// A failed write fails the request, because a token nobody can audit is not
// allowed to stand. The engine calls this before it returns the token, so a
// refusal here means the client never receives one.
func tokenAudit(tenantID string, rec *audit.Recorder) goidc.HandleTokenFunc {
	return func(ctx context.Context, tkn *goidc.Token, grant *goidc.Grant) error {
		return rec.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    grant.Subject,
			Action:     audit.ActionTokenIssued,
			EntityType: "grant",
			EntityID:   grant.ID,
			Metadata: map[string]any{
				"client_id": grant.ClientID,
				"grant_id":  grant.ID,
				"scopes":    tkn.Scopes,
			},
		})
	}
}
