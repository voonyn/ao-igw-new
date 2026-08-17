package session

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The sentinels the administrative routes answer with. A domain registers its
// own, so no other package maps an error it does not declare.
//
// A person who administers nothing and a person who administers one
// organization read the same 403 and the same slug. The answer never reports
// which seats somebody else holds.
func init() {
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrNoSuchSession, fiber.StatusNotFound, "not_found", "Not Found")
}

// AdminHandler serves the login sessions of a tenant to the console. It binds
// the request, calls the service, and writes the envelope. No rule lives here.
type AdminHandler struct {
	svc *AdminService
	log logger.Logger
}

func NewAdminHandler(svc *AdminService, log logger.Logger) *AdminHandler {
	return &AdminHandler{svc: svc, log: log}
}

// AdminRoutes mounts the session routes. The caller mounts the tenant middleware
// and the bearer middleware on the group, so every route below reads a resolved
// tenant and a verified subject.
//
// The list sorts by the three columns the console offers. Any other key is
// refused with 422.
//
// The force-logout hangs off the person and not off the session, because it ends
// every session they hold and the operator names nobody's session in particular.
func AdminRoutes(router fiber.Router, h *AdminHandler) {
	router.Get("/sessions", middlewares.Paginate("created", "expires", "state"), h.list)
	router.Delete("/sessions/:id", h.revoke)
	router.Delete("/users/:id/sessions", h.revokeForUser)
}

func (h *AdminHandler) list(c fiber.Ctx) error {
	rows, total, err := h.svc.List(c.Context(), actorFrom(c), queryFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.List(c, rows, total)
}

func (h *AdminHandler) revoke(c fiber.Ctx) error {
	view, err := h.svc.Revoke(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *AdminHandler) revokeForUser(c fiber.Ctx) error {
	view, err := h.svc.RevokeForUser(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
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
	// An empty sort key is not an error. The repository then reads newest
	// first, the way every other admin list does.
	sort, desc := middlewares.SortFrom(c)

	q := Query{
		UserID: c.Query("userId"),
		OrgID:  c.Query("orgId"),
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
