package session

import (
	"context"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	apioidc "alphaomega/identitygateway/internal/api/oidc"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// bearerPrefix is how the login UI presents the session token.
const bearerPrefix = "Bearer "

// The sentinels this domain answers with. The mapper owns every status code, so
// no handler below maps one itself.
//
// The five answer alike, slug and message, so the response never says whether
// the identifier, the password, the login session, a directory that is switched
// off, or a spent bind budget is what failed.
//
// The last two carry no slug of their own on purpose, and both would be an
// enumeration oracle at the password step if they did. A disabled directory
// would name every person tied to it for as long as it stays off. A spent bind
// budget is worse, because a caller drives it: only a directory sign-in carries
// a budget, so a slug of its own would say that an identifier is served by a
// directory, and eleven wrong guesses would ask the question whenever the
// attacker liked. The audit trail names both, because an operator reads it.
func init() {
	response.Map(ErrBadCredentials, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
	response.Map(ErrLoginSessionNotFound, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
	response.Map(ErrNotAuthenticated, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
	response.Map(ErrSubjectBound, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
	response.Map(ErrDirectoryDisabled, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
	response.Map(ErrTooManyBinds, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")

	// A directory that did not answer is not a wrong password, so it carries a
	// slug of its own and the person is told to try again. The slug says that
	// the identifier is served by a directory, and that is paid for on purpose:
	// the state is transient, and the person needs to call the right helpdesk.
	response.Map(ErrDirectoryUnavailable, fiber.StatusServiceUnavailable,
		"directory_unavailable", "Service Unavailable")

	// This one carries its own slug. A person who owes a factor proved their
	// password, so the sign-in resumes at the step they skipped instead of
	// starting again, and only a slug of its own tells the login UI that.
	response.Map(ErrInsufficientFactors, fiber.StatusUnauthorized,
		"insufficient_factors", "Additional verification is required")
}

// Handler serves the login steps the login UI drives. It binds the request,
// calls the service, and writes the envelope. No rule lives here.
type Handler struct {
	sessions *Service
	complete apioidc.Completer
	describe ScopeDescriber
	log      logger.Logger
}

// ScopeDescriber reads the words the consent screen renders for the scopes it
// asks about.
type ScopeDescriber func(ctx context.Context, tenantID string, names []string) ([]oidc.Scope, error)

func NewHandler(
	sessions *Service, complete apioidc.Completer,
	describe ScopeDescriber, log logger.Logger,
) *Handler {
	return &Handler{sessions: sessions, complete: complete, describe: describe, log: log}
}

// Routes mounts the login steps. The caller mounts the tenant middleware on the
// group, because every step needs the tenant of the request.
func Routes(router fiber.Router, h *Handler) {
	router.Use(requireTenant)
	router.Post("/identifier", h.identifier)
	router.Post("/password", h.password)
	router.Post("/complete", h.completeLogin)
	router.Post("/consent", h.consent)
	router.Post("/logout", h.logout)
	router.Get("/session", h.status)
}

// requireTenant answers a request that reached a login route with no resolved
// tenant. Every route below reads the tenant, so the check lives here once and
// each handler then reads it without a guard of its own.
func requireTenant(c fiber.Ctx) error {
	if _, ok := middlewares.TenantFrom(c); !ok {
		return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
	}
	return c.Next()
}

// identifier opens a partial login session for one identifier.
func (h *Handler) identifier(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	var req IdentifierRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	opened, err := h.sessions.Identify(
		c.Context(), tc.TenantID, req.Identifier, c.IP(), c.Get(fiber.HeaderUserAgent))
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, IdentifierResponse{
		SessionID:    opened.ID,
		SessionToken: opened.Token,
	})
}

// password verifies the password of the person the login session names.
//
// A refused password and a dead session answer 401 alike, so the response never
// says which of them happened. The authn session of an authorization request is
// not touched here, because only the finalize step writes it.
func (h *Handler) password(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	var req PasswordRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	upgraded, steps, err := h.sessions.VerifyPassword(c.Context(), tc.TenantID, token, req.Password)
	if err != nil {
		return response.Fail(c, err)
	}
	if steps == nil {
		steps = []string{}
	}

	return response.OK(c, PasswordResponse{
		SessionToken: upgraded.Token,
		Methods:      steps,
	})
}

// completeLogin finalizes one authorization request against the login session.
//
// The person is named on the authn session, and the answer carries the browser
// back to the protocol engine. A request that still needs the person answers
// 401, and the login UI then renders the sign-in flow.
func (h *Handler) completeLogin(c fiber.Ctx) error {
	var req CompleteRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}
	return h.finalize(c, req.AuthRequest, nil)
}

// consent records the answer the person gave on the consent screen, and then
// finalizes the same authorization request.
//
// An approval and a refusal both answer with a redirect. A refusal carries the
// browser back to the protocol engine too, which then tells the client that the
// person said no.
func (h *Handler) consent(c fiber.Ctx) error {
	var req ConsentRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}
	return h.finalize(c, req.AuthRequest, &req.Approved)
}

// finalize runs the finalize step of one authorization request. answered is nil
// for the finalize step, and holds the answer for the consent step.
func (h *Handler) finalize(c fiber.Ctx, authRequest string, answered *bool) error {
	tc, _ := middlewares.TenantFrom(c)

	// A dead session is not an error here. The completer decides what a silent
	// request gets, and only it can write the marker that answers one.
	//
	// A session that owes a factor is an error, and it falls to the default arm.
	// It proved a password, so the answer names the step the person skipped and
	// the login UI routes them back to it.
	var live LoginSession
	if token := bearerToken(c); token != "" {
		resolved, err := h.sessions.ResolveForFinalize(c.Context(), tc.TenantID, token)
		switch {
		case err == nil:
			live = resolved
		case errors.Is(err, ErrLoginSessionNotFound), errors.Is(err, ErrNotAuthenticated):
		default:
			return response.Fail(c, err)
		}
	}

	out, err := h.complete(c.Context(), apioidc.Completion{
		TenantID:      tc.TenantID,
		Issuer:        tc.Config.Issuer,
		AuthRequestID: authRequest,
		Subject:       live.UserID,
		SessionID:     live.ID,
		Factors:       live.FactorNames(),
		AuthTime:      live.AuthTime(),
		Consent:       answered,
		IP:            c.IP(),
		UserAgent:     c.Get(fiber.HeaderUserAgent),
	})
	if err != nil {
		return response.Fail(c, err)
	}

	if out.ConsentRequired {
		return response.OK(c, CompleteResponse{
			ConsentRequired: true,
			Client:          &ConsentClient{ClientID: out.ClientID},
			Scopes:          h.consentScopes(c, tc.TenantID, out.Scopes),
		})
	}
	return response.OK(c, CompleteResponse{RedirectTo: out.RedirectTo})
}

// consentScopes is what the consent screen renders. A scope the tenant
// describes carries its own words, and every other scope falls back to the bare
// name.
//
// A failed read is not an error for the person. The screen still names every
// scope, so the sign-in continues and the failure is logged once.
func (h *Handler) consentScopes(c fiber.Ctx, tenantID string, names []string) []ConsentScope {
	described, err := h.describe(c.Context(), tenantID, names)
	if err != nil {
		h.log.Error("describe scopes",
			logger.String("tenant_id", tenantID), logger.Err(err))
		described = nil
		for _, name := range names {
			described = append(described, oidc.Scope{Name: name, DisplayName: name})
		}
	}

	scopes := make([]ConsentScope, 0, len(described))
	for _, scope := range described {
		scopes = append(scopes, ConsentScope{
			Name:        scope.Name,
			DisplayName: scope.DisplayName,
			Description: scope.Description,
		})
	}
	return scopes
}

// logout ends the login session the presented token credentials.
//
// An absent token, a dead one, and a live one all answer 200. The three answer
// alike, so the response never says which of them happened, and a person who
// signs out twice is not told that the first attempt already worked.
func (h *Handler) logout(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	token := bearerToken(c)
	if token == "" {
		return response.OK(c, LogoutResponse{})
	}

	err := h.sessions.Logout(c.Context(), tc.TenantID, token)
	if err != nil && !errors.Is(err, ErrLoginSessionNotFound) {
		return response.Fail(c, err)
	}
	return response.OK(c, LogoutResponse{})
}

// status reports whether the presented token credentials a fully authenticated
// login session.
//
// An absent token, a dead one, and a session that carries no factor all answer
// {"active":false}. The three answer alike, so the response never says which of
// them happened.
func (h *Handler) status(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	token := bearerToken(c)
	if token == "" {
		return response.OK(c, StatusResponse{})
	}

	live, err := h.sessions.Resolve(c.Context(), tc.TenantID, token)
	if errors.Is(err, ErrLoginSessionNotFound) || errors.Is(err, ErrNotAuthenticated) {
		return response.OK(c, StatusResponse{})
	}
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, StatusResponse{Active: true, Email: live.Email})
}

// bearerToken reads the session token off the Authorization header. The token
// is a credential, so the caller never logs the value.
func bearerToken(c fiber.Ctx) string {
	header := c.Get(fiber.HeaderAuthorization)
	if len(header) <= len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerPrefix):])
}
