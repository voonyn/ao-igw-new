package user

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

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
func AccountRoutes(router fiber.Router, h *AccountHandler) {
	router.Post("/profile", h.updateProfile)
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
