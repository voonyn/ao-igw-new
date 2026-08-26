package middlewares

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/actor"
)

// ActorFrom reads the person behind one administrative request.
//
// The tenant middleware and the bearer guard both ran before any handler that
// calls this, so both values are on the request. A route that mounts neither
// reads an empty actor, and the service refuses it on the role check.
//
// Every domain handler called its own copy of this before. The copies were
// identical, and a domain that answers a write it does not audit is the one
// case a copy could drift into.
func ActorFrom(c fiber.Ctx) actor.Actor {
	tc, _ := TenantFrom(c)
	subject, _ := SubjectFrom(c)

	return actor.Actor{
		TenantID:  tc.TenantID,
		UserID:    subject,
		IP:        c.IP(),
		UserAgent: c.Get(fiber.HeaderUserAgent),
	}
}
