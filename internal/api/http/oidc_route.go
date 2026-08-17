package http

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	aooidc "alphaomega/identitygateway/internal/api/oidc"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// discoveryPath is where the specification puts the discovery document. It sits
// at the root, outside the prefix the other endpoints share.
const discoveryPath = "/.well-known/openid-configuration"

// registrationMethods are the client management methods the protocol engine
// serves. The engine refuses a registration itself, so only these three need a
// route of their own.
var registrationMethods = []string{fiber.MethodGet, fiber.MethodPut, fiber.MethodDelete}

// tokenPath is where the protocol engine issues a token. The engine fixes the
// name, and the route is declared here so the token endpoint alone can carry
// the transaction middleware.
const tokenPath = "/token"

// logoutPath is where the protocol engine ends a sign-in. The engine fixes the
// name, and the route is declared here so the logout endpoint alone can carry
// the transaction middleware.
const logoutPath = "/logout"

// mountOIDC mounts the protocol endpoints of every tenant. The tenant
// middleware resolves the host first, and the registry then answers with that
// tenant's provider.
func mountOIDC(
	app *fiber.App, prefix string, tenantMW fiber.Handler,
	reg *aooidc.Registry, tx db.TxRunner, log logger.Logger,
) {
	handler := aooidc.Handler(reg, log)
	app.Get(discoveryPath, tenantMW, handler)

	// The client store makes the protocol engine serve the registration
	// management endpoints. Dynamic client registration is out of scope, so
	// these are refused here, before the catch-all reaches the provider. Fiber
	// matches in registration order, so this route must come first.
	app.Add(registrationMethods, prefix+"/register/*", refuseRegistration)

	// The token endpoint saves the grant and records token.issued. Both writes
	// belong to one transaction, so this route is declared before the catch-all
	// and carries the transaction middleware. Fiber matches in registration
	// order.
	app.Post(prefix+tokenPath, tenantMW, middlewares.InTx(tx, log), handler)

	// The logout endpoint terminates the login session, revokes the grants it
	// produced, and records logout.succeeded. Every write belongs to one
	// transaction, so this route carries the transaction middleware too.
	app.Add([]string{fiber.MethodGet, fiber.MethodPost},
		prefix+logoutPath, tenantMW, middlewares.InTx(tx, log), handler)

	app.All(prefix+"/*", tenantMW, handler)
}

// refuseRegistration answers as if the registration endpoints did not exist.
// A client row is created by an operator, never over HTTP.
func refuseRegistration(c fiber.Ctx) error {
	return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
}
