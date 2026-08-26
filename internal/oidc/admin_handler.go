package oidc

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinels the provider routes answer with. ErrForbidden is registered by
// the grant service of this domain, so it is not registered again here.
//
// A tenant with no provider config answers 404. The console names the missing
// subsystem, which is a different sentence from a refusal.
func init() {
	response.Map(ErrProviderConfigNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrOpaqueAccessToken, fiber.StatusUnprocessableEntity, "invalid_input",
		"An opaque access token is not served by this gateway.")

	// ErrForbidden belongs to the grant read of this package. Its route is
	// served from internal/session, because the grant hangs off the session the
	// person holds. The sentinel is declared here, so it is registered here: no
	// package maps an error it does not declare.
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")

	// ErrSessionNotFound belongs to the authn session store of this package. Its
	// routes are served from internal/api/oidc, and it is registered here for
	// the same reason as ErrForbidden. A login step that names an authorization
	// request the gateway does not hold gets 400: the request is bad, and the
	// credentials are not.
	response.Map(ErrSessionNotFound, fiber.StatusBadRequest, "session_not_found", "Bad Request")
}

// AdminActorReader reads the person behind one request.
//
// The tenant middleware and the bearer guard put both values on the request, and
// this package cannot read them back itself: internal/api/http/middlewares
// imports this package for the provider config of the resolved tenant, so
// importing it here would close the cycle. The router therefore passes the
// reader in.
type AdminActorReader func(c fiber.Ctx) AdminActor

// AdminHandler serves the protocol settings and the signing keys of a tenant to
// the console. It binds the request, calls the service, and writes the envelope.
// No rule lives here.
type AdminHandler struct {
	svc   *AdminService
	actor AdminActorReader
}

func NewAdminHandler(svc *AdminService, actor AdminActorReader) *AdminHandler {
	return &AdminHandler{svc: svc, actor: actor}
}

// AdminRoutes mounts the provider routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// Both reads are of one tenant and are bounded, so neither is paged. Key
// rotation is a scheduled operation and has no route.
func AdminRoutes(router fiber.Router, h *AdminHandler) {
	router.Get("/provider", h.readProvider)
	router.Patch("/provider", h.updateProvider)
	router.Get("/keys", h.listKeys)
}

func (h *AdminHandler) readProvider(c fiber.Ctx) error {
	view, err := h.svc.ReadProvider(c.Context(), h.actor(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *AdminHandler) updateProvider(c fiber.Ctx) error {
	var body ProviderConfigBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.UpdateProvider(c.Context(), h.actor(c), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *AdminHandler) listKeys(c fiber.Ctx) error {
	views, err := h.svc.ListKeys(c.Context(), h.actor(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, views)
}
