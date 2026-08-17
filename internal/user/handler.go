package user

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/logger"
)

// SlugNotAConsoleUser is what a person without an administrative role reads. The
// console branches on it and sends the person to the portal.
const SlugNotAConsoleUser = "not_a_console_user"

// The sentinels this domain answers with. A domain registers its own, so no
// other package maps an error it does not declare.
//
// A person the tenant disabled, and an id nobody holds, both answer 401 and the
// slug the bearer guard writes, so the response never says which people a
// tenant holds.
// A person who administers nothing and a person who administers another
// organization read the same 403 and the same slug. The answer never reports
// which organizations somebody else administers.
func init() {
	response.Map(ErrNotFound, fiber.StatusUnauthorized, middlewares.SlugUnauthenticated, "Unauthorized")
	response.Map(ErrNoAdminRole, fiber.StatusForbidden, SlugNotAConsoleUser, "Forbidden")
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrNoSuchUser, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrDuplicateUsername, fiber.StatusConflict, "duplicate_username",
		"Another account of this tenant already holds that username.")
	response.Map(ErrLastOwner, fiber.StatusConflict, "last_owner",
		"The tenant must keep one IAM_OWNER. Grant the role to somebody else first.")
}

// Handler serves the admin front door. It binds the request, calls the service,
// and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
	log logger.Logger
}

func NewHandler(svc *Service, log logger.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

// AdminRoutes mounts the admin front door. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
// The list sorts by the three columns the console offers. Any other key is
// refused with 422, so an operator never reads a page ordered by a question they
// did not ask.
func AdminRoutes(router fiber.Router, h *Handler) {
	router.Get("/me", h.me)

	router.Get("/users", middlewares.Paginate("created", "username", "state"), h.list)
	router.Get("/users/:id", h.find)
	router.Post("/users", h.create)
	router.Patch("/users/:id", h.update)
	router.Delete("/users/:id", h.remove)
	router.Post("/users/:id/activate", h.activate)
	router.Post("/users/:id/deactivate", h.deactivate)
	router.Post("/users/:id/unlock", h.unlock)
	router.Post("/users/:id/password-reset", h.resetPassword)
	router.Delete("/users/:id/mfa", h.resetMFA)
	router.Get("/users/:id/memberships", h.memberships)

	// An invitation writes an account and the membership that puts it in one
	// organization, so it lives with the accounts and not with the rosters.
	router.Post("/invitations", h.invite)
}

// me answers the person the access token names.
//
// A person who holds none of the four administrative roles reads 403 and the
// slug not_a_console_user. The bearer middleware already refused every caller
// that carries no valid token.
func (h *Handler) me(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)
	subject, _ := middlewares.SubjectFrom(c)

	me, err := h.svc.Me(c.Context(), tc.TenantID, subject)
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, me)
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

// invite answers the new token exactly once. Nothing sends it yet and nothing
// logs it, so an operator who loses it invites again.
func (h *Handler) invite(c fiber.Ctx) error {
	var body InviteBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.Invite(c.Context(), actorFrom(c), body)
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

func (h *Handler) activate(c fiber.Ctx) error {
	if err := h.svc.Activate(c.Context(), actorFrom(c), c.Params("id")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

func (h *Handler) deactivate(c fiber.Ctx) error {
	if err := h.svc.Deactivate(c.Context(), actorFrom(c), c.Params("id")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

func (h *Handler) unlock(c fiber.Ctx) error {
	if err := h.svc.Unlock(c.Context(), actorFrom(c), c.Params("id")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// resetPassword answers the new token exactly once. Nothing stores it and
// nothing logs it, so an operator who loses it resets again.
func (h *Handler) resetPassword(c fiber.Ctx) error {
	view, err := h.svc.ResetPassword(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) resetMFA(c fiber.Ctx) error {
	if err := h.svc.ResetMFA(c.Context(), actorFrom(c), c.Params("id")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

func (h *Handler) memberships(c fiber.Ctx) error {
	view, err := h.svc.Memberships(c.Context(), actorFrom(c), c.Params("id"))
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
	sort, desc := middlewares.SortFrom(c)

	q := Query{
		Search:   c.Query("q"),
		State:    fiber.Query(c, "state", 0),
		UserType: fiber.Query(c, "type", 0),
		OrgID:    c.Query("orgId"),
		Sort:     sort,
		Desc:     desc,
		Limit:    1,
	}
	if info, ok := paginate.FromContext(c); ok && info != nil {
		q.Limit, q.Offset = info.Limit, info.Start()
	}
	return q
}
