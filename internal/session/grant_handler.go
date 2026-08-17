package session

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// GrantHandler serves the grants of a tenant to the console. It binds the
// request, calls the grant service, and writes the envelope. No rule lives here.
//
// The route sits in this package and not in internal/oidc, because
// internal/api/http/middlewares reads oidc.ProviderConfig and the oidc domain
// therefore cannot import the middleware its handler would need. The screen is
// one screen: the console renders the grants beside the login sessions they fan
// out from, and terminating a session revokes them.
type GrantHandler struct {
	svc *oidc.GrantService
	log logger.Logger
}

func NewGrantHandler(svc *oidc.GrantService, log logger.Logger) *GrantHandler {
	return &GrantHandler{svc: svc, log: log}
}

// GrantRoutes mounts the grant route. The caller mounts the tenant middleware
// and the bearer middleware on the group, so the route below reads a resolved
// tenant and a verified subject.
//
// The list sorts by the two columns the console offers. Any other key is refused
// with 422.
func GrantRoutes(router fiber.Router, h *GrantHandler) {
	router.Get("/grants", middlewares.Paginate("created", "expires"), h.list)
}

func (h *GrantHandler) list(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)
	subject, _ := middlewares.SubjectFrom(c)

	rows, total, err := h.svc.List(c.Context(),
		oidc.GrantActor{TenantID: tc.TenantID, UserID: subject}, grantQueryFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.List(c, rows, total)
}

// grantQueryFrom reads the window and the narrowing of one list read. The
// paginate middleware already clamped the limit and refused an unknown sort key.
func grantQueryFrom(c fiber.Ctx) oidc.GrantQuery {
	// An empty sort key is not an error. The repository then reads newest
	// first, the way every other admin list does.
	sort, desc := middlewares.SortFrom(c)

	q := oidc.GrantQuery{
		UserID: c.Query("userId"),
		Sort:   sort,
		Desc:   desc,
		Limit:  1,
	}
	if info, ok := paginate.FromContext(c); ok && info != nil {
		q.Limit, q.Offset = info.Limit, info.Start()
	}
	return q
}
