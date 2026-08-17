package organization

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/logger"
)

// SlugDefaultOrg is what an operator reads when they try to delete the
// organization self-registration points at. The console branches on it and says
// why the delete cannot happen.
const SlugDefaultOrg = "default_org"

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
	response.Map(ErrDefaultOrg, fiber.StatusConflict, SlugDefaultOrg,
		"The default organization cannot be deleted.")
}

// Handler serves the organizations of a tenant to the console. It binds the
// request, calls the service, and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
	log logger.Logger
}

func NewHandler(svc *Service, log logger.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

// AdminRoutes mounts the organization routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// The list sorts by the three columns the console offers. Any other key is
// refused with 422, so an operator never reads a page ordered by a question
// they did not ask.
func AdminRoutes(router fiber.Router, h *Handler) {
	router.Get("/organizations", middlewares.Paginate("created", "name", "state"), h.list)
	router.Get("/organizations/:id", h.find)
	router.Post("/organizations", h.create)
	router.Patch("/organizations/:id", h.update)
	router.Delete("/organizations/:id", h.remove)
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
	var body Body
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.Create(c.Context(), actorFrom(c), body.Name)
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

	view, err := h.svc.Update(c.Context(), actorFrom(c), c.Params("id"), body.Name)
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

// actorFrom reads the person behind the request. The tenant middleware and the
// bearer guard both ran, so both values are present.
func actorFrom(c fiber.Ctx) Actor {
	tc, _ := middlewares.TenantFrom(c)
	subject, _ := middlewares.SubjectFrom(c)

	return Actor{
		TenantID:  tc.TenantID,
		UserID:    subject,
		IP:        c.IP(),
		UserAgent: c.Get(fiber.HeaderUserAgent),
	}
}

// queryFrom reads the window and the narrowing of one list read. The paginate
// middleware already clamped the limit and refused an unknown sort key.
func queryFrom(c fiber.Ctx) Query {
	sort, desc := middlewares.SortFrom(c)

	q := Query{
		Search: c.Query("q"),
		State:  fiber.Query(c, "state", 0),
		Sort:   sort,
		Desc:   desc,
		Limit:  1,
	}
	if info, ok := paginate.FromContext(c); ok && info != nil {
		q.Limit, q.Offset = info.Limit, info.Start()
	}
	return q
}
