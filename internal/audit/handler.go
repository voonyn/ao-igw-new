package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinel the feed answers with. A domain registers its own, so no other
// package maps an error it does not declare.
func init() {
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
}

// SortKeys names the columns the feed sorts by. Migration 00025 indexes
// (tenant_id, created_at), and no other ordering of this table is indexed, so a
// second key would filesort the trail of the tenant.
//
// The router builds the pagination middleware from this list. This package
// cannot build it itself: internal/api/http/middlewares resolves a host to its
// tenant through internal/tenant, and internal/tenant records its own writes
// through this package.
var SortKeys = []string{"created"}

// ActorReader reads the person behind one request. The router supplies it, for
// the same reason SortKeys is exported: the middleware that holds the resolved
// tenant cannot be imported here.
type ActorReader func(c fiber.Ctx) Actor

// Handler serves the audit trail of a tenant to the console. It reads the
// request, calls the service, and writes the envelope. No rule lives here.
type Handler struct {
	svc   *Service
	actor ActorReader
}

func NewHandler(svc *Service, actor ActorReader) *Handler {
	return &Handler{svc: svc, actor: actor}
}

// AdminRoutes mounts the audit route. The caller mounts the tenant middleware
// and the bearer middleware on the group, so the route below reads a resolved
// tenant and a verified subject.
//
// pager is middlewares.Paginate built over SortKeys. The trail is read and never
// written, so this is the whole surface.
func AdminRoutes(router fiber.Router, h *Handler, pager fiber.Handler) {
	router.Get("/audit", pager, h.list)
}

func (h *Handler) list(c fiber.Ctx) error {
	q, err := queryFrom(c)
	if err != nil {
		return response.ErrorSlug(c, fiber.StatusUnprocessableEntity, "invalid_input", err.Error())
	}

	rows, total, err := h.svc.List(c.Context(), h.actor(c), q)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.List(c, rows, total)
}

// queryFrom reads the window and the narrowing of one read of the feed. The
// pagination middleware already clamped the limit and refused an unknown sort
// key.
//
// A timestamp the gateway cannot read is refused rather than dropped. A dropped
// bound would answer the whole trail to an operator who asked for one hour, and
// nothing on the screen would say so.
func queryFrom(c fiber.Ctx) (Query, error) {
	from, err := timeQuery(c, "from")
	if err != nil {
		return Query{}, err
	}
	to, err := timeQuery(c, "to")
	if err != nil {
		return Query{}, err
	}

	q := Query{
		Actor:      c.Query("actor"),
		Action:     c.Query("action"),
		EntityType: c.Query("entity_type"),
		EntityID:   c.Query("entity_id"),
		From:       from,
		To:         to,
	}

	pageFrom(c, &q)
	return q, nil
}

// pageFrom reads the window and the order of one page onto q. Both feeds of this
// package page the same way, so the reading lives here once.
//
// The sort is read from Fiber's own middleware, and the direction from the
// console's `dir` parameter. middlewares.SortFrom does the same, and this package
// cannot import it.
func pageFrom(c fiber.Ctx, q *Query) {
	if info, ok := paginate.FromContext(c); ok && info != nil {
		q.Limit, q.Offset = info.Limit, info.Start()
		if len(info.Sort) > 0 {
			q.Sort, q.Desc = info.Sort[0].Field, info.Sort[0].Order == paginate.DESC
		}
	}
	if dir := c.Query("dir"); dir != "" {
		q.Desc = strings.EqualFold(dir, "desc")
	}
}

// timeQuery reads one RFC 3339 bound of the range. An absent bound is not a
// bound, and an unreadable one is an error.
func timeQuery(c fiber.Ctx, name string) (time.Time, error) {
	value := c.Query(name)
	if value == "" {
		return time.Time{}, nil
	}

	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("Cannot read %q as a time. Write it as RFC 3339, for example 2026-08-17T09:00:00Z.", name)
	}
	return at, nil
}
