package totp

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// bearerPrefix is how the sign-in front end presents the Login Session token.
const bearerPrefix = "Bearer "

// The sentinels this domain answers with. The mapper owns every status code, so
// no handler below maps one itself.
//
// A session that proved no password answers the one unauthenticated slug every
// other login step answers, so the response never says whether the session, the
// password step, or the enrolment is what failed.
//
// A wrong code answers invalid_credentials, which is the slug the sign-in front
// end renders as a wrong code. Answering the unauthenticated slug would tell the
// person their email or password was wrong, which it was not.
//
// The two caps on guessing answer slugs of their own. too_many_codes says the
// sign-in ended and the person must start again, and rate_limited says the
// person must wait. A generic failure would leave the login UI unable to say
// either, and the person would keep typing into a session that is dead.
//
// A budget nobody could read answers mfa_unavailable, not rate_limited. It is
// the gateway that failed, not the person who guessed too much, so the answer
// asks them to try again rather than to wait out a window that is not counting.
//
// A sign-in enrolment for a person who already holds a Second Factor answers a
// slug of its own, and not mfa_already_enrolled. The two name different states
// and ask for different things: one tells a person in the portal to remove the
// Authenticator they hold, and mfa_already_held tells the sign-in front end it
// offered a step the account does not owe. The passkey module answers the same
// slug for the same refusal, so the front end reads one value for one rule.
func init() {
	response.Map(ErrPasswordNotProved, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
	response.Map(ErrBadCode, fiber.StatusUnauthorized, "invalid_credentials", "Unauthorized")
	response.Map(ErrAlreadyEnrolled, fiber.StatusConflict, "mfa_already_enrolled", "Conflict")
	response.Map(ErrFactorAlreadyHeld, fiber.StatusConflict, "mfa_already_held", "Conflict")
	response.Map(ErrNoPendingEnrolment, fiber.StatusConflict, "no_pending_enrolment", "Conflict")
	response.Map(ErrNoActiveFactor, fiber.StatusConflict, "no_active_factor", "Conflict")
	response.Map(ErrSignInEnded, fiber.StatusUnauthorized, "too_many_codes", "Unauthorized")
	response.Map(ErrTooManyAttempts, fiber.StatusTooManyRequests, "rate_limited", "Too Many Requests")
	response.Map(ErrBudgetUnavailable, fiber.StatusServiceUnavailable, "mfa_unavailable", "Service Unavailable")
}

// Handler serves the enrolment steps of the sign-in. It binds the request, calls
// the service, and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// LoginRoutes mounts the two enrolment steps the sign-in front end drives. The
// caller mounts the login credential of the front end and the tenant middleware
// on the group, the same way it mounts them on the other login steps.
func LoginRoutes(router fiber.Router, h *Handler) {
	router.Use(requireTenant)
	router.Post("/totp/enroll/start", h.start)
	router.Post("/totp/enroll/activate", h.activate)
	router.Post("/verify", h.verify)
}

// requireTenant answers a request that reached an enrolment route with no
// resolved tenant. Both routes below read the tenant, so the check lives here
// once.
func requireTenant(c fiber.Ctx) error {
	if _, ok := middlewares.TenantFrom(c); !ok {
		return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
	}
	return c.Next()
}

// start hands the person a pending secret and the provisioning URI behind it.
func (h *Handler) start(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	started, err := h.svc.Start(c.Context(), tc.TenantID, tc.Config.Issuer, token)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, StartResponse{Secret: started.Secret, OtpauthURI: started.OtpauthURI})
}

// activate proves the pending secret and answers the rotated token beside the
// Recovery Codes.
func (h *Handler) activate(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	var req ActivateRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	activated, err := h.svc.Activate(c.Context(), tc.TenantID, token, req.Code)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, ActivateResponse{
		SessionToken:  activated.SessionToken,
		RecoveryCodes: activated.RecoveryCodes,
	})
}

// verify answers the challenge and hands back the rotated token.
//
// The address names no kind of code, because one field carries both. A person
// who reaches for a Recovery Code sends it here.
func (h *Handler) verify(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	var req VerifyRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	rotated, err := h.svc.Verify(c.Context(), tc.TenantID, token, req.Code)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, VerifyResponse{SessionToken: rotated})
}

// bearerToken reads the Login Session token off the Authorization header. The
// token is a credential, so the caller never logs the value.
func bearerToken(c fiber.Ctx) string {
	header := c.Get(fiber.HeaderAuthorization)
	if len(header) <= len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerPrefix):])
}
