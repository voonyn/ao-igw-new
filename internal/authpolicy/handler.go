package authpolicy

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinels this domain answers with. A domain registers its own, so no
// other package maps an error it does not declare.
//
// organization.ErrNotFound reaches these routes when an org id names nothing,
// and the organization package already maps it.
//
// A person who administers nothing and a person who administers another
// organization read the same 403 and the same slug. The answer never reports
// which organizations somebody else administers.
func init() {
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrTenantScope, fiber.StatusConflict, "tenant_scope",
		"The tenant default has no level to inherit from and cannot be reset.")

	// Every password write in the gateway checks against this policy, so the
	// refusal is registered here, beside the rules it comes from. The message
	// names no rule: see ErrWeakPassword.
	response.Map(ErrWeakPassword, fiber.StatusBadRequest, "weak_password",
		"That password does not meet the password policy.")
}

// Handler serves the auth policy of a tenant to the console. It binds the
// request, calls the service, and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// AdminRoutes mounts the auth-policy routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// The two levels are the same three fields of one path: an empty organization
// is the tenant default, and a named one is that organization's override. The
// reset exists at organization level only, because the tenant default has
// nothing to inherit.
func AdminRoutes(router fiber.Router, h *Handler) {
	router.Get("/settings/auth", h.read)
	router.Put("/settings/auth", h.write)

	router.Get("/orgs/:orgId/settings/auth", h.read)
	router.Put("/orgs/:orgId/settings/auth", h.write)
	router.Delete("/orgs/:orgId/settings/auth", h.reset)
}

func (h *Handler) read(c fiber.Ctx) error {
	view, err := h.svc.Read(c.Context(), actorFrom(c), c.Params("orgId"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) write(c fiber.Ctx) error {
	var body Body
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.Write(c.Context(), actorFrom(c), c.Params("orgId"), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) reset(c fiber.Ctx) error {
	if err := h.svc.Reset(c.Context(), actorFrom(c), c.Params("orgId")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// actorFrom reads the person behind the request. The tenant middleware and the
// bearer guard both ran, so both values are present.
func actorFrom(c fiber.Ctx) Actor { return Actor(middlewares.ActorFrom(c)) }
