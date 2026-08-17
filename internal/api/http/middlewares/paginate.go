package middlewares

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/response"
)

const (
	defaultPageLimit = 20
	maxPageLimit     = 100
)

// Paginate mounts Fiber's pagination middleware with the gateway defaults, so
// every list route reads `?page=`, `?limit=`, and `?sort=` the same way. A limit
// above maxPageLimit is clamped, not rejected.
//
// allowedSorts names the columns a caller may sort by. Pass the column names, and
// never build an ORDER BY clause from raw query input. The first name is the
// default sort.
//
// A sort key outside the allowlist is refused with 422, and the message names the
// permitted set. Fiber drops such a key and sorts by the default instead, which
// answers a different question from the one the operator asked.
func Paginate(allowedSorts ...string) fiber.Handler {
	next := paginate.New(paginate.Config{
		DefaultPage:  1,
		DefaultLimit: defaultPageLimit,
		MaxLimit:     maxPageLimit,
		SortKey:      "sort",
		AllowedSorts: allowedSorts,
	})

	permitted := strings.Join(allowedSorts, ", ")

	return func(c fiber.Ctx) error {
		for _, key := range strings.Split(c.Query("sort"), ",") {
			key = strings.TrimPrefix(strings.TrimSpace(key), "-")
			if key == "" || slices.Contains(allowedSorts, key) {
				continue
			}
			return response.ErrorSlug(c, fiber.StatusUnprocessableEntity, "invalid_input",
				fmt.Sprintf("Cannot sort by %q. This list sorts by: %s.", key, permitted))
		}
		return next(c)
	}
}

// SortFrom reports the column one list read sorts by, and whether it reads
// downwards. An empty key means the list keeps its own default order.
//
// The console sends the direction as its own `dir` parameter, and Fiber's
// middleware reads a `-` prefix instead, so the two are read together here. A
// key outside the allowlist never arrives, because Paginate refuses it.
func SortFrom(c fiber.Ctx) (string, bool) {
	var key string
	var desc bool

	if info, ok := paginate.FromContext(c); ok && info != nil && len(info.Sort) > 0 {
		key = info.Sort[0].Field
		desc = info.Sort[0].Order == paginate.DESC
	}
	if dir := c.Query("dir"); dir != "" {
		desc = strings.EqualFold(dir, "desc")
	}
	return key, desc
}
