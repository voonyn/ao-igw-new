package middlewares

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/logger"
)

// basicPrefix is how a caller presents an HTTP Basic credential.
const basicPrefix = "Basic "

// StaticBasic admits only a caller that presents one fixed HTTP Basic
// credential. The push callback of the Scan Verifier is the one route behind it:
// the callback carries no tenant and no person, and its success signs somebody
// in, so it is never mounted open.
//
// The comparison runs over digests, so it takes the same time for a credential of
// any length and for no credential at all. The credential never reaches a log
// line.
//
// An empty half refuses every request. The caller decides not to mount the route
// at all, so a misconfiguration cannot leave the route open.
func StaticBasic(clientID, clientSecret string, log logger.Logger) fiber.Handler {
	want := sha256.Sum256([]byte(clientID + ":" + clientSecret))
	usable := clientID != "" && clientSecret != ""

	return func(c fiber.Ctx) error {
		presented := sha256.Sum256(decodeBasic(c.Get(fiber.HeaderAuthorization)))
		if usable && subtle.ConstantTimeCompare(presented[:], want[:]) == 1 {
			return c.Next()
		}

		log.Warn("push callback credential rejected", logger.String("path", c.Path()))
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}
}

// decodeBasic reads the "id:secret" bytes off an Authorization header. A header
// that is absent, of another scheme, or not base64 gives an empty result, which
// no configured credential matches.
func decodeBasic(header string) []byte {
	if len(header) <= len(basicPrefix) || !strings.EqualFold(header[:len(basicPrefix)], basicPrefix) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(basicPrefix):]))
	if err != nil {
		return nil
	}
	return raw
}
