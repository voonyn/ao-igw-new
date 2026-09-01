package identityprovider

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
	response.Map(ErrNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrLinkNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrUserNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrNotAdmin, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrDomainClaimed, fiber.StatusConflict, "domain_already_claimed",
		"Another identity provider of this tenant already claims that domain.")
	response.Map(ErrNameTaken, fiber.StatusConflict, "name_conflict",
		"Another identity provider of this tenant already carries that name.")
	response.Map(ErrLevelFixed, fiber.StatusConflict, "level_fixed",
		"An identity provider stays at the level it was created at.")
	response.Map(ErrServerScheme, fiber.StatusUnprocessableEntity, "invalid_input",
		"A server does not match the transport. LDAPS takes ldaps://, and the other two take ldap://.")

	// A spent budget answers rate_limited, which is the slug both other budgets
	// of this gateway answer with. A budget nobody could read answers a slug of
	// its own, because the two ask the administrator for different things: one
	// to wait, and one to call an operator.
	response.Map(ErrTooManyTests, fiber.StatusTooManyRequests, "rate_limited", "Too Many Requests")
	response.Map(ErrTestUnavailable, fiber.StatusServiceUnavailable, "test_unavailable",
		"The connection test cannot run at the moment.")
}

// Handler serves the identity providers of a tenant to the console. It binds the
// request, calls the service, and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// AdminRoutes mounts the identity provider routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// The provider list is bounded — a tenant registers a handful of directories, and
// two of them already cost it the bare-username route — so it answers whole and
// it carries no pager.
//
// The level of a provider is a field of the body, not a path segment, because a
// provider does not move between levels once it is created.
//
// linkId is the id of the identity provider. One person holds at most one account
// per provider, which the unique key enforces, so the provider names exactly one
// link of one person.
func AdminRoutes(router fiber.Router, h *Handler) {
	router.Get("/identity-providers", h.list)
	router.Post("/identity-providers", h.create)
	router.Get("/identity-providers/:id", h.find)
	router.Put("/identity-providers/:id", h.update)
	router.Delete("/identity-providers/:id", h.remove)

	// Two paths reach one connection test. The path with an id tests a stored
	// provider, and the path without one tests a configuration nobody saved yet,
	// so an administrator checks a directory before the first save.
	router.Post("/identity-providers/test", h.test)
	router.Post("/identity-providers/:id/test", h.test)

	router.Get("/users/:id/identity-links", h.links)
	router.Delete("/users/:id/identity-links/:linkId", h.unlink)
}

func (h *Handler) list(c fiber.Ctx) error {
	rows, err := h.svc.List(c.Context(), actorFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, rows)
}

func (h *Handler) find(c fiber.Ctx) error {
	view, err := h.svc.Find(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) create(c fiber.Ctx) error {
	var body Body
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.Create(c.Context(), actorFrom(c), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.Created(c, view)
}

func (h *Handler) update(c fiber.Ctx) error {
	var body Body
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.Update(c.Context(), actorFrom(c), c.Params("id"), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) remove(c fiber.Ctx) error {
	if err := h.svc.Delete(c.Context(), actorFrom(c), c.Params("id")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// test dials the directory of one provider and answers which stage failed.
//
// The body is the form the console has on screen, so a test runs against values
// nobody saved yet. A test of a stored provider carries no body, which is how an
// administrator tests one without retyping its bind password.
//
// The path without an id has nothing stored to fall back on, so it requires the
// body and the validator answers a missing one.
func (h *Handler) test(c fiber.Ctx) error {
	idpID := c.Params("id")

	var body *Body
	if idpID == "" || len(c.Body()) > 0 {
		var sent Body
		if err := c.Bind().Body(&sent); err != nil {
			return response.Validation(c, err)
		}
		body = &sent
	}

	result, err := h.svc.Test(c.Context(), actorFrom(c), idpID, body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, result)
}

func (h *Handler) links(c fiber.Ctx) error {
	rows, err := h.svc.Links(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, rows)
}

func (h *Handler) unlink(c fiber.Ctx) error {
	err := h.svc.Unlink(c.Context(), actorFrom(c), c.Params("id"), c.Params("linkId"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// actorFrom reads the person behind the request. The tenant middleware and the
// bearer guard both ran, so both values are present.
func actorFrom(c fiber.Ctx) Actor { return Actor(middlewares.ActorFrom(c)) }
