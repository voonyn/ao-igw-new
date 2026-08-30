package passkey

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// AdminHandler serves an operator the Passkeys of somebody else. It binds the
// request, calls the service, and writes the envelope. No rule lives here.
type AdminHandler struct {
	svc *AdminService
}

func NewAdminHandler(svc *AdminService) *AdminHandler {
	return &AdminHandler{svc: svc}
}

// AdminRoutes mounts the console Passkey routes. The caller mounts the tenant
// middleware and the bearer guard on the group, so both routes below read a
// resolved tenant and a verified subject.
//
// There are two routes and there is no third. No route here registers a Passkey
// for another person, at any privilege: a Factor belongs to the person who holds
// the device, and the ceremony runs on the portal alone.
//
// The list answers one bounded whole. A person holds at most ten Passkeys, so it
// mounts no pager, the way the memberships route does not.
func AdminRoutes(router fiber.Router, h *AdminHandler) {
	router.Get("/users/:id/passkeys", h.list)
	router.Delete("/users/:id/passkeys/:credentialId", h.revoke)
}

// list answers the live Passkeys of the person the address names.
func (h *AdminHandler) list(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	rows, err := h.svc.List(c.Context(), tc.TenantID, principal(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, views(rows))
}

// revoke marks one Passkey of that person as removed.
//
// The address is DELETE and carries no body. The operator holds no password of
// that person, so there is nothing to send: the role check is the whole proof,
// which is what the console reset beside it runs on.
func (h *AdminHandler) revoke(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	if err := h.svc.Revoke(
		c.Context(), tc.TenantID, principal(c), c.Params("id"), c.Params("credentialId"),
	); err != nil {
		return response.Fail(c, err)
	}

	return response.NoContent(c)
}
