package application

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinels this domain answers with. A domain registers its own, so no
// other package maps an error it does not declare.
//
// A person who administers nothing and a person who administers another
// organization read the same 403 and the same slug. The answer never reports
// which organizations somebody else administers.
func init() {
	response.Map(ErrNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrNotAdmin, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrNoClient, fiber.StatusConflict, "no_client",
		"This application holds no OIDC client.")
	response.Map(ErrPublicClient, fiber.StatusConflict, "public_client",
		"A public client authenticates with PKCE and holds no secret.")
}

// Handler serves the applications of a tenant to the console. It binds the
// request, calls the service, and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// AdminRoutes mounts the application routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// The list sorts by the three columns the console offers. Any other key is
// refused with 422, so an operator never reads a page ordered by a question
// they did not ask.
func AdminRoutes(router fiber.Router, h *Handler) {
	router.Get("/applications", middlewares.Paginate("created", "name", "state"), h.list)
	router.Get("/applications/:id", h.find)
	router.Post("/applications", h.create)
	router.Patch("/applications/:id", h.update)
	router.Delete("/applications/:id", h.remove)
	router.Post("/applications/:id/rotate-secret", h.rotateSecret)
}

func (h *Handler) list(c fiber.Ctx) error {
	rows, total, err := h.svc.List(c.Context(), actorFrom(c), queryFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.List(c, rows, total)
}

func (h *Handler) find(c fiber.Ctx) error {
	view, err := h.svc.Find(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) create(c fiber.Ctx) error {
	var body CreateBody
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
	var body UpdateBody
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

// rotateSecret answers the new secret exactly once. Nothing stores it, and
// nothing logs it, so an operator who loses it rotates again.
func (h *Handler) rotateSecret(c fiber.Ctx) error {
	view, err := h.svc.RotateSecret(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

// actorFrom reads the person behind the request. The tenant middleware and the
// bearer guard both ran, so both values are present.
func actorFrom(c fiber.Ctx) Actor { return Actor(middlewares.ActorFrom(c)) }

// queryFrom reads the window and the narrowing of one list read. The paginate
// middleware already clamped the limit and refused an unknown sort key.
func queryFrom(c fiber.Ctx) Query {
	sort, desc := middlewares.SortFrom(c)

	q := Query{
		Search: c.Query("q"),
		State:  fiber.Query(c, "state", 0),
		OrgID:  c.Query("orgId"),
		Sort:   sort,
		Desc:   desc,
	}
	if info, ok := paginate.FromContext(c); ok && info != nil {
		q.Limit, q.Offset = info.Limit, info.Start()
	}
	return q
}
