package totp

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// AccountHandler serves a person their own Second Factor. It binds the request,
// calls the service, and writes the envelope. No rule lives here.
type AccountHandler struct {
	svc *Service
}

func NewAccountHandler(svc *Service) *AccountHandler {
	return &AccountHandler{svc: svc}
}

// AccountRoutes mounts the self-service second-factor routes. The caller mounts
// the tenant middleware and the bearer guard on the group, so every route below
// reads a resolved tenant and a verified subject.
//
// The two enrolment addresses repeat the shape of the sign-in path, one prefix
// down. The same two steps run there, so a reader who knows one knows the other.
// The two addresses below are POST and not DELETE, because each one carries a
// body: the current password is the whole proof of the request, and a body on a
// DELETE is what proxies and clients drop.
func AccountRoutes(router fiber.Router, h *AccountHandler) {
	router.Get("/mfa", h.status)
	router.Post("/mfa/totp/enroll/start", h.start)
	router.Post("/mfa/totp/enroll/activate", h.activate)
	router.Post("/mfa/totp/remove", h.remove)
	router.Post("/mfa/totp/recovery-codes", h.replaceRecoveryCodes)
}

// status answers whether a factor is active, when it was activated, and how many
// Recovery Codes remain.
func (h *AccountHandler) status(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	view, err := h.svc.AccountStatus(c.Context(), tc.TenantID, accountPrincipal(c))
	if err != nil {
		return response.Fail(c, err)
	}

	answer := StatusResponse{Active: view.Active, RecoveryCodesRemaining: view.RecoveryRemaining}
	if view.Active {
		answer.ActivatedAt = &view.ActivatedAt
	}
	return response.OK(c, answer)
}

// start hands the person a pending secret and the provisioning URI behind it.
func (h *AccountHandler) start(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	started, err := h.svc.AccountStart(c.Context(), tc.TenantID, tc.Config.Issuer, accountPrincipal(c))
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, StartResponse{Secret: started.Secret, OtpauthURI: started.OtpauthURI})
}

// activate proves the pending secret and answers the Recovery Codes.
func (h *AccountHandler) activate(c fiber.Ctx) error {
	var req ActivateRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	tc, _ := middlewares.TenantFrom(c)

	codes, err := h.svc.AccountActivate(c.Context(), tc.TenantID, accountPrincipal(c), req.Code)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, RecoveryCodesResponse{RecoveryCodes: codes})
}

// remove destroys the Second Factor of the person the token names, once they
// present the password stored now.
//
// Nothing is answered but the empty envelope. The page re-reads the state, and a
// removal that answered the state would be a second copy of the status rules.
func (h *AccountHandler) remove(c fiber.Ctx) error {
	var req PasswordProofRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	tc, _ := middlewares.TenantFrom(c)

	if err := h.svc.AccountRemove(c.Context(), tc.TenantID, accountPrincipal(c), req.Password); err != nil {
		return response.Fail(c, err)
	}

	return response.NoContent(c)
}

// replaceRecoveryCodes voids every Recovery Code of the person the token names
// and answers a fresh set, once they present the password stored now.
func (h *AccountHandler) replaceRecoveryCodes(c fiber.Ctx) error {
	var req PasswordProofRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Validation(c, err)
	}

	tc, _ := middlewares.TenantFrom(c)

	codes, err := h.svc.AccountReplaceRecoveryCodes(
		c.Context(), tc.TenantID, accountPrincipal(c), req.Password)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, RecoveryCodesResponse{RecoveryCodes: codes})
}

// accountPrincipal reads the person behind one portal request.
//
// It names no login session, because the portal holds an access token and no
// sign-in is in flight. PasswordProved is left false for the same reason: it
// guards the sign-in path, where a session exists before a password is proved,
// and the bearer guard has already decided this request.
func accountPrincipal(c fiber.Ctx) Principal {
	who := middlewares.ActorFrom(c)
	return Principal{UserID: who.UserID, IP: who.IP, UserAgent: who.UserAgent}
}
