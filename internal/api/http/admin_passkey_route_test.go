package http

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/passkey"
)

// TestAdminPasskeyRoutesReadAndRevokeOnly pins the whole console Passkey
// surface: a read and a revoke, and nothing that creates a Factor.
//
// A Passkey belongs to the person who holds the device. The ceremony proves that
// device to the gateway, and an operator has no device to prove, so a
// registration route here could only ever write a Factor nobody can answer with.
// The rule is easy to break by copying the portal mount, so the mount is pinned.
func TestAdminPasskeyRoutesReadAndRevokeOnly(t *testing.T) {
	app := fiber.New()
	group := app.Group(adminPrefix)

	// The service is never called. This test asks what was mounted, and nothing
	// else.
	passkey.AdminRoutes(group, passkey.NewAdminHandler(nil))

	want := map[string]bool{
		fiber.MethodGet + " " + adminPrefix + "/users/:id/passkeys":                  true,
		fiber.MethodDelete + " " + adminPrefix + "/users/:id/passkeys/:credentialId": true,
	}

	mounted := map[string]bool{}
	for _, route := range app.GetRoutes() {
		// Fiber mounts a HEAD beside every GET of its own accord, and the
		// framework answers it. It is not a route this module declared.
		if route.Method == fiber.MethodHead {
			continue
		}
		if !strings.Contains(route.Path, "passkeys") {
			continue
		}
		mounted[route.Method+" "+route.Path] = true
	}

	for address := range want {
		if !mounted[address] {
			t.Errorf("the console calls %s and the gateway mounts no such route", address)
		}
	}
	for address := range mounted {
		if !want[address] {
			t.Errorf("the gateway mounts %s, and the console surface is a read and a revoke", address)
		}
	}
}
