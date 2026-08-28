package http

import (
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/totp"
	"alphaomega/identitygateway/internal/user"
)

// accountContract is every address the portal calls on the account API.
//
// The portal defines the contract. It is a complete front end, and the gateway
// is built to match what it already calls. Each line below is read from a proxy
// route under web/portal-ui/src/app/api/account.
var accountContract = []string{
	fiber.MethodPost + " " + accountPrefix + "/profile",
	fiber.MethodPost + " " + accountPrefix + "/password",
	fiber.MethodGet + " " + accountPrefix + "/sessions",
	fiber.MethodDelete + " " + accountPrefix + "/sessions",
	fiber.MethodDelete + " " + accountPrefix + "/sessions/:id",
	fiber.MethodGet + " " + accountPrefix + "/activity",
	fiber.MethodGet + " " + accountPrefix + "/connected-apps",
	fiber.MethodDelete + " " + accountPrefix + "/connected-apps/:clientId",
	fiber.MethodGet + " " + accountPrefix + "/mfa",
	fiber.MethodPost + " " + accountPrefix + "/mfa/totp/enroll/start",
	fiber.MethodPost + " " + accountPrefix + "/mfa/totp/enroll/activate",
	fiber.MethodPost + " " + accountPrefix + "/mfa/totp/remove",
	fiber.MethodPost + " " + accountPrefix + "/mfa/totp/recovery-codes",
}

// TestAccountRoutesMatchThePortal pins the addresses of the account API against
// the front end that calls them. Nothing else crosses this seam: a service test
// proves the rule, and a route the portal cannot reach passes every one of them.
//
// The five domains mount their own routes, so no one file holds the whole list.
// This test is that list.
func TestAccountRoutesMatchThePortal(t *testing.T) {
	app := fiber.New()
	group := app.Group(accountPrefix)

	// The services are never called. This test asks what was mounted, and
	// nothing else.
	user.AccountRoutes(group, user.NewAccountHandler(nil))
	oidc.AccountRoutes(group, oidc.NewAccountHandler(nil, nil))
	session.AccountRoutes(group, session.NewAccountHandler(nil))
	audit.AccountRoutes(group, audit.NewAccountHandler(nil, nil), passThrough)
	totp.AccountRoutes(group, totp.NewAccountHandler(nil))

	mounted := map[string]bool{}
	for _, route := range app.GetRoutes() {
		mounted[route.Method+" "+route.Path] = true
	}

	for _, want := range accountContract {
		if !mounted[want] {
			t.Errorf("the portal calls %s and the gateway mounts no such route", want)
		}
	}
}
