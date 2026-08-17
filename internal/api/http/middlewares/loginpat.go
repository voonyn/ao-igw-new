package middlewares

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/logger"
)

// LoginPATHeader is where the login UI presents its personal access token. The
// token names the caller, never a person.
const LoginPATHeader = "X-Login-UI-PAT"

// LoginPAT admits only the login UI to the login steps. The steps open a
// session for any identifier, so an open endpoint would let anyone mint
// sessions and probe the tenant.
//
// The set holds every accepted token, so a rotation can run with the old token
// and the new one live at once. An empty set refuses every request.
//
// The comparison runs over digests, so it takes the same time for a token of
// any length and for no token at all. The token never reaches a log line.
func LoginPAT(pats []string, log logger.Logger) fiber.Handler {
	allowed := make([][sha256.Size]byte, len(pats))
	for i, pat := range pats {
		allowed[i] = sha256.Sum256([]byte(pat))
	}

	return func(c fiber.Ctx) error {
		presented := sha256.Sum256([]byte(c.Get(LoginPATHeader)))

		match := 0
		for _, want := range allowed {
			match |= subtle.ConstantTimeCompare(presented[:], want[:])
		}
		if match == 1 {
			return c.Next()
		}

		log.Warn("login PAT rejected", logger.String("path", c.Path()))
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}
}
