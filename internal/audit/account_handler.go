package audit

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/response"
)

// AccountHandler serves a person their own activity feed. It reads the request,
// calls the service, and writes the envelope. No rule lives here.
type AccountHandler struct {
	svc   *AccountService
	actor ActorReader
}

func NewAccountHandler(svc *AccountService, actor ActorReader) *AccountHandler {
	return &AccountHandler{svc: svc, actor: actor}
}

// AccountRoutes mounts the activity route. The caller mounts the tenant
// middleware and the bearer guard on the group, so the route below reads a
// resolved tenant and a verified subject.
//
// pager is middlewares.Paginate built over SortKeys, the same value the console
// feed takes. The feed pages by offset, as every list of this deployment does.
// The portal reads page numbers from the meta the envelope carries.
func AccountRoutes(router fiber.Router, h *AccountHandler, pager fiber.Handler) {
	router.Get("/activity", pager, h.list)
}

// list answers one page of the events the caller caused.
//
// The read carries the window and the order and nothing else. The console feed
// narrows by action, by entity, and by time range, and the portal asks for none
// of that, so this route offers none of it either.
func (h *AccountHandler) list(c fiber.Ctx) error {
	rows, total, err := h.svc.List(c.Context(), h.actor(c), accountQueryFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.List(c, rows, total)
}

// accountQueryFrom reads the window and the order of one page. The pagination
// middleware already clamped the limit and refused an unknown sort key, and the
// service names the actor, so nothing is left to read from the request.
//
// A read that asks for no order reads newest first.
func accountQueryFrom(c fiber.Ctx) Query {
	var q Query
	if info, ok := paginate.FromContext(c); ok && info != nil {
		q.Limit, q.Offset = info.Limit, info.Start()
		if len(info.Sort) > 0 {
			q.Sort, q.Desc = info.Sort[0].Field, info.Sort[0].Order == paginate.DESC
		}
	}
	if dir := c.Query("dir"); dir != "" {
		q.Desc = strings.EqualFold(dir, "desc")
	}
	return q
}
