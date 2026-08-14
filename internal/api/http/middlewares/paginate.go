package middlewares

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"
)

const (
	defaultPageLimit = 20
	maxPageLimit     = 100
)

// Paginate mounts Fiber's pagination middleware with the gateway defaults, so
// every list route reads `?page=` and `?limit=` the same way. A limit above
// maxPageLimit is clamped, not rejected.
//
// allowedSorts names the columns a caller may sort by. Pass the column names, and
// never build an ORDER BY clause from raw query input.
func Paginate(allowedSorts ...string) fiber.Handler {
	return paginate.New(paginate.Config{
		DefaultPage:  1,
		DefaultLimit: defaultPageLimit,
		MaxLimit:     maxPageLimit,
		AllowedSorts: allowedSorts,
	})
}
