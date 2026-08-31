package passkey

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// bearerPrefix is how the sign-in front end presents the Login Session token.
const bearerPrefix = "Bearer "

// The sentinels the sign-in half answers with. The account handler maps every
// sentinel the two halves share, so only the four below are mapped here.
//
// A session that proved no password answers the one unauthenticated slug every
// other login step answers, so the response never says whether the session or
// the password step is what failed.
//
// A person who holds no Passkey answers a slug of its own. Only the password
// answer routes a person to this step, so the front end reads it as a step it
// must not have offered, and it moves to the other Second Factor.
//
// A credential of another person answers a slug of its own too. It is the one
// refusal a person can act on: they picked the wrong device.
//
// A person who already holds a Second Factor answers mfa_already_held, which is
// the slug the TOTP module answers for the same refusal. One rule reads as one
// value, so the front end handles it in one place: it offered an enrolment step
// for an account that owes a challenge.
//
// Too many challenge starts answer rate_limited, which is the slug both other
// second-factor budgets answer. The three are separate counters, and a person who
// waits out one never learns which of them refused.
func init() {
	response.Map(ErrPasswordNotProved, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
	response.Map(ErrNoPasskey, fiber.StatusConflict, "no_passkey", "Conflict")
	response.Map(ErrFactorAlreadyHeld, fiber.StatusConflict, "mfa_already_held", "Conflict")
	response.Map(ErrCredentialUnknown,
		fiber.StatusUnauthorized, "passkey_unknown_credential", "Unauthorized")
	response.Map(ErrTooManyChallenges,
		fiber.StatusTooManyRequests, "rate_limited", "Too Many Requests")
}

// Handler serves the Passkey challenge of the sign-in. It binds the request,
// calls the service, and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// LoginRoutes mounts the four steps of the sign-in: the Passkey challenge a
// holder answers, and the enrolment a person the MFA Requirement governs runs
// instead. The caller mounts the login credential of the front end and the
// tenant middleware on the group, the same way it mounts them on the other login
// steps.
//
// The four addresses are siblings of the TOTP routes, and they repeat the shape
// of the self-service pair one prefix down. The same steps run everywhere, so a
// reader who knows one knows the others.
//
// Nothing is mounted on the group itself. The TOTP routes share it, so a guard
// installed here would run on every one of theirs too. Each handler below reads
// the tenant it needs and refuses a host no tenant claims.
func LoginRoutes(router fiber.Router, h *Handler) {
	router.Post("/passkey/challenge/start", h.challengeStart)
	router.Post("/passkey/challenge/finish", h.challengeFinish)
	router.Post("/passkey/enroll/start", h.enrolStart)
	router.Post("/passkey/enroll/finish", h.enrolFinish)
}

// enrolStart answers the registration options the browser passes to
// navigator.credentials.create().
//
// The whole object is answered as it stands, the way the challenge options are.
// The sign-in front end hands it to the browser untouched.
func (h *Handler) enrolStart(c fiber.Ctx) error {
	tc, ok := middlewares.TenantFrom(c)
	if !ok {
		return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
	}

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	creation, err := h.svc.LoginEnrolStart(c.Context(), tc.TenantID, tc.Host, origin(c), token)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, creation)
}

// enrolFinish stores the proved Passkey and hands back the rotated token. It
// answers the same shape the challenge finish answers, so the sign-in front end
// reads one field at both steps.
func (h *Handler) enrolFinish(c fiber.Ctx) error {
	var req ChallengeFinishRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	tc, ok := middlewares.TenantFrom(c)
	if !ok {
		return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
	}

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	rotated, err := h.svc.LoginEnrolFinish(
		c.Context(), tc.TenantID, tc.Host, origin(c), token, req.Credential)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, ChallengeResponse{SessionToken: rotated})
}

// challengeStart answers the assertion options the browser passes to
// navigator.credentials.get().
//
// The whole object is answered as it stands. The sign-in front end hands it to
// the browser untouched, because every field of it is part of what the device
// will sign.
func (h *Handler) challengeStart(c fiber.Ctx) error {
	tc, ok := middlewares.TenantFrom(c)
	if !ok {
		return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
	}

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	assertion, err := h.svc.LoginStart(c.Context(), tc.TenantID, tc.Host, origin(c), token)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, assertion)
}

// challengeFinish verifies the assertion and hands back the rotated token.
func (h *Handler) challengeFinish(c fiber.Ctx) error {
	var req ChallengeFinishRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	tc, ok := middlewares.TenantFrom(c)
	if !ok {
		return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
	}

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	rotated, err := h.svc.LoginFinish(
		c.Context(), tc.TenantID, tc.Host, origin(c), token, req.Credential)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, ChallengeResponse{SessionToken: rotated})
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
