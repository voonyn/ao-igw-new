package passkey

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinels this domain answers with. The mapper owns every status code, so
// no handler below maps one itself.
//
// Each failure carries a slug of its own, because the front end acts differently
// on each. An expired challenge asks the person to press the button again. A
// refused origin is a deployment problem the person cannot fix, and the copy
// says so. A refused answer asks them to try the device again.
//
// A ceremony the gateway could not run answers 503. It is the gateway that
// failed, not the person, so the answer asks them to try again rather than to
// change anything.
func init() {
	response.Map(ErrOriginRefused, fiber.StatusBadRequest, "passkey_origin_refused", "Bad Request")
	response.Map(ErrChallengeExpired, fiber.StatusConflict, "passkey_challenge_expired", "Conflict")
	response.Map(ErrRejected, fiber.StatusUnauthorized, "passkey_rejected", "Unauthorized")
	response.Map(ErrCeremonyUnavailable,
		fiber.StatusServiceUnavailable, "passkey_unavailable", "Service Unavailable")
}

// AccountHandler serves a person their own Passkeys. It binds the request, calls
// the service, and writes the envelope. No rule lives here.
type AccountHandler struct {
	svc *Service
}

func NewAccountHandler(svc *Service) *AccountHandler {
	return &AccountHandler{svc: svc}
}

// AccountRoutes mounts the self-service Passkey routes. The caller mounts the
// tenant middleware and the bearer guard on the group, so every route below
// reads a resolved tenant and a verified subject.
//
// The two addresses repeat the shape of the sign-in path, one prefix down. The
// same two steps run there, so a reader who knows one knows the other.
//
// The list answers one bounded whole. A person holds at most ten Passkeys, so it
// mounts no pager, the way the memberships route does not.
func AccountRoutes(router fiber.Router, h *AccountHandler) {
	router.Get("/mfa/passkeys", h.list)
	router.Post("/mfa/passkeys/register/start", h.start)
	router.Post("/mfa/passkeys/register/finish", h.finish)
}

// list answers the live Passkeys of the person the token names.
func (h *AccountHandler) list(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	rows, err := h.svc.AccountList(c.Context(), tc.TenantID, accountPrincipal(c))
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, views(rows))
}

// start answers the registration options the browser passes to
// navigator.credentials.create().
//
// The whole object is answered as it stands. The portal hands it to the browser
// untouched, because every field of it is part of what the device will sign.
func (h *AccountHandler) start(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	creation, err := h.svc.AccountRegisterStart(
		c.Context(), tc.TenantID, tc.Host, origin(c), accountPrincipal(c))
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, creation)
}

// finish verifies the answer of the browser and stores the Passkey.
func (h *AccountHandler) finish(c fiber.Ctx) error {
	var req RegisterFinishRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	tc, _ := middlewares.TenantFrom(c)

	row, err := h.svc.AccountRegisterFinish(
		c.Context(), tc.TenantID, tc.Host, origin(c), req.Name,
		accountPrincipal(c), req.Credential)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.Created(c, view(row))
}

// origin reads the origin the browser calls from.
//
// Every browser sends the header on a POST, so a request without one is not the
// browser this ceremony is for. The service decides what to do with an empty
// value, because the rule is a rule of the ceremony and not of the transport.
func origin(c fiber.Ctx) string { return c.Get(fiber.HeaderOrigin) }

// accountPrincipal reads the person behind one portal request.
//
// It names no login session, because the portal holds an access token and no
// sign-in is in flight. The bearer guard has already decided this request.
func accountPrincipal(c fiber.Ctx) Principal {
	who := middlewares.ActorFrom(c)
	return Principal{UserID: who.UserID, IP: who.IP, UserAgent: who.UserAgent}
}
