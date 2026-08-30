package tenant

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// SlugPrimaryDomain is what an operator reads when they try to remove the host
// the tenant issues its tokens from. The console branches on it and says why the
// removal cannot happen.
const SlugPrimaryDomain = "primary_domain"

// SlugRegistrableDomain is what an operator reads when the new host does not
// share the registrable domain of the hosts the tenant already serves. The
// console branches on it and names the rule on the domain form.
const SlugRegistrableDomain = "registrable_domain"

// The sentinels this domain answers with. A domain registers its own, so no
// other package maps an error it does not declare.
//
// A host another tenant holds and a host nobody holds answer alike, so the
// answer never reports which tenants exist.
func init() {
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrTenantNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrDomainNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrNoBootstrapRecord, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrDomainTaken, fiber.StatusConflict, "name_conflict",
		"That host is already mapped to a tenant.")
	response.Map(ErrPrimaryDomain, fiber.StatusConflict, SlugPrimaryDomain,
		"The primary domain cannot be removed.")
	response.Map(ErrRegistrableDomain, fiber.StatusConflict, SlugRegistrableDomain,
		"That host does not share the registrable domain of this tenant.")
}

// ActorReader reads the person behind one request.
//
// The tenant middleware and the bearer guard put both values on the request, and
// this package cannot read them back itself: internal/api/http/middlewares
// imports this package to resolve a host to its tenant, so importing it here
// would close the cycle. The router therefore passes the reader in.
type ActorReader func(c fiber.Ctx) Actor

// AdminHandler serves the tenant record to the console. It binds the request,
// calls the service, and writes the envelope. No rule lives here.
type AdminHandler struct {
	svc   *AdminService
	actor ActorReader
}

func NewAdminHandler(svc *AdminService, actor ActorReader) *AdminHandler {
	return &AdminHandler{svc: svc, actor: actor}
}

// AdminRoutes mounts the tenant routes. The caller mounts the tenant middleware
// and the bearer middleware on the group, so every route below reads a resolved
// tenant and a verified subject.
//
// Every route is scoped to the caller's own tenant. The tenant comes from the
// resolved host and never from the path, so no route can address another tenant.
//
// The tenant lifecycle itself stays in the bootstrap command. Only the hostnames
// are written here.
func AdminRoutes(router fiber.Router, h *AdminHandler) {
	router.Get("/tenant", h.read)
	router.Post("/tenant/domains", h.addDomain)
	router.Delete("/tenant/domains/:domain", h.removeDomain)
	router.Get("/bootstrap", h.bootstrap)
}

func (h *AdminHandler) read(c fiber.Ctx) error {
	view, err := h.svc.Read(c.Context(), h.actor(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *AdminHandler) addDomain(c fiber.Ctx) error {
	var body AddDomainBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.AddDomain(c.Context(), h.actor(c), body.Domain)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.Created(c, view)
}

func (h *AdminHandler) removeDomain(c fiber.Ctx) error {
	if err := h.svc.RemoveDomain(c.Context(), h.actor(c), c.Params("domain")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

func (h *AdminHandler) bootstrap(c fiber.Ctx) error {
	view, err := h.svc.ReadBootstrap(c.Context(), h.actor(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}
