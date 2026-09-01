package user

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinel the self-service half of this domain answers with.
//
// A wrong current password and a token whose account can no longer sign in read
// one 401 and one slug. The portal branches on the slug and asks the person for
// the current password again.
func init() {
	response.Map(ErrBadPassword, fiber.StatusUnauthorized, "invalid_credentials",
		"The current password is wrong.")

	// A password the Directory owns cannot be changed here. The portal hides the
	// control, so this refusal reaches a person only when the account changed
	// under an open screen.
	response.Map(ErrPasswordNotLocal, fiber.StatusConflict, "password_not_local",
		"Your password is managed by your organization's directory. Change it there.")

	// A directory that could not answer is not a wrong password. The person is
	// told to try again, and never that the password they typed is wrong.
	response.Map(ErrDirectoryUnavailable, fiber.StatusServiceUnavailable,
		"directory_unavailable", "Service Unavailable")
}

// AccountHandler serves the self-service account API. It binds the request,
// calls the service, and writes the envelope. No rule lives here.
type AccountHandler struct {
	svc *AccountService
}

func NewAccountHandler(svc *AccountService) *AccountHandler {
	return &AccountHandler{svc: svc}
}

// AccountRoutes mounts the self-service routes this domain owns. The caller
// mounts the tenant middleware and the bearer guard on the group, so every route
// below reads a resolved tenant and a verified subject.
//
// There is no profile read. The userinfo endpoint already releases the fields
// the portal renders, under the tenant's own scope and claim mapper
// configuration, and a second read would answer them under a second set of
// rules about who sees what.
// The password change takes the caller's own login session in the except query
// parameter, the same name the session revoke takes it under. The portal reads
// sid from the ID token it holds and sends it, so the device the person is using
// survives the change and every other one ends.
func AccountRoutes(router fiber.Router, h *AccountHandler) {
	router.Get("/password", h.passwordState)
	router.Post("/profile", h.updateProfile)
	router.Post("/password", h.changePassword)
}

// passwordState says whether the person the token names holds a local password.
func (h *AccountHandler) passwordState(c fiber.Ctx) error {
	local, err := h.svc.PasswordLocal(c.Context(), actorFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, PasswordStateView{Local: local})
}

// updateProfile writes the identity fields of the person the token names.
func (h *AccountHandler) updateProfile(c fiber.Ctx) error {
	var body ProfileBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	if err := h.svc.UpdateProfile(c.Context(), actorFrom(c), body); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// changePassword replaces the password of the person the token names, once they
// present the one stored now.
func (h *AccountHandler) changePassword(c fiber.Ctx) error {
	var body PasswordBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	if err := h.svc.ChangePassword(c.Context(), actorFrom(c), body, c.Query("except")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}
