package middlewares

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gofiber/fiber/v3"
	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/logger"
)

// SlugUnauthenticated is the slug every refusal of the bearer guard carries. The
// four refusals answer alike, so the answer never says why a token failed.
const SlugUnauthenticated = "unauthenticated"

// subjectLocalsKey names the verified subject in the request locals.
const subjectLocalsKey = "ao_subject"

// KeySetFinder reads the public key set of one tenant.
// oidc.KeyService.PublicKeySet has this shape.
type KeySetFinder func(ctx context.Context, tenantID string) (goidc.JSONWebKeySet, error)

// Bearer admits a request that carries a valid access token of the resolved
// tenant, and refuses every other request with 401.
//
// It runs behind the Tenant middleware, which names the tenant the token must
// come from. The token is a JWT, and it is verified here against the tenant's
// published key set: the signature, then iss, exp, and aud. No store is read, so
// a token stays valid until it expires, even after a logout. See
// internal/api/oidc/logout.go.
//
// resource is the identifier this API answers for. A token that names another
// resource is refused, so a token minted for the account API cannot reach the
// admin API.
//
// The token never reaches a log line. A refusal logs the path and the tenant id.
func Bearer(keys KeySetFinder, resource string, log logger.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		tc, ok := TenantFrom(c)
		if !ok {
			// The guard is mounted without the Tenant middleware in front of
			// it, which is a wiring fault and not a bad request. It logs at
			// error, once, and answers the same slug as every other refusal, so
			// the client still learns nothing.
			log.Error("bearer guard runs without a resolved tenant", logger.String("path", c.Path()))
			return response.ErrorSlug(c, fiber.StatusUnauthorized, SlugUnauthenticated, "Unauthorized")
		}

		raw := bearerToken(c.Get(fiber.HeaderAuthorization))
		if raw == "" {
			return refuse(c, log, tc.TenantID, "no bearer token")
		}

		jwks, err := keys(c.Context(), tc.TenantID)
		if err != nil {
			log.Error("read the key set of the tenant",
				logger.String("tenant_id", tc.TenantID), logger.Err(err))
			return err
		}

		algs := signatureAlgs(jwks)
		if len(algs) == 0 {
			log.Error("tenant publishes no verifiable key",
				logger.String("tenant_id", tc.TenantID))
			return refuse(c, log, tc.TenantID, "no verifiable key")
		}

		token, err := jwt.ParseSigned(raw, algs)
		if err != nil {
			return refuse(c, log, tc.TenantID, "malformed token")
		}

		var claims jwt.Claims
		if err := token.Claims(jwks.ToJOSE(), &claims); err != nil {
			return refuse(c, log, tc.TenantID, "signature does not verify")
		}

		err = claims.ValidateWithLeeway(jwt.Expected{
			Issuer:      tc.Config.Issuer,
			AnyAudience: jwt.Audience{resource},
			Time:        time.Now(),
		}, 0)
		if err != nil {
			return refuse(c, log, tc.TenantID, "claims do not validate")
		}
		if claims.Subject == "" {
			return refuse(c, log, tc.TenantID, "token names no subject")
		}

		log.Debug("bearer token accepted",
			logger.String("tenant_id", tc.TenantID),
			logger.String("user_id", claims.Subject))

		c.Locals(subjectLocalsKey, claims.Subject)
		return c.Next()
	}
}

// SubjectFrom returns the user id the bearer middleware verified.
func SubjectFrom(c fiber.Ctx) (string, bool) {
	subject, ok := c.Locals(subjectLocalsKey).(string)
	return subject, ok
}

// refuse answers 401 and logs the reason once. The reason stays in the log, and
// the client reads one slug for every refusal.
func refuse(c fiber.Ctx, log logger.Logger, tenantID, reason string) error {
	log.Warn("bearer token rejected",
		logger.String("tenant_id", tenantID),
		logger.String("path", c.Path()),
		logger.String("reason", reason))
	return response.ErrorSlug(c, fiber.StatusUnauthorized, SlugUnauthenticated, "Unauthorized")
}

// bearerToken reads the token out of an Authorization header. The scheme is
// compared without case, as RFC 7235 requires.
func bearerToken(header string) string {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// signatureAlgs lists the algorithms the tenant's key set can verify. The list
// is the allow-list the parser takes, so a token that names any other algorithm
// is refused before a key is read.
//
// `alg` is optional in a JWK, as RFC 7517 section 4.4 states. A key that omits
// it falls back to what its own type can verify. A tenant whose published key
// set names no algorithm therefore still admits a valid token, instead of
// refusing every admin request.
func signatureAlgs(jwks goidc.JSONWebKeySet) []jose.SignatureAlgorithm {
	algs := make([]jose.SignatureAlgorithm, 0, len(jwks.Keys))
	add := func(alg jose.SignatureAlgorithm) {
		if alg == "" || alg == "none" || slices.Contains(algs, alg) {
			return
		}
		algs = append(algs, alg)
	}

	for _, key := range jwks.Keys {
		if key.Algorithm != "" {
			add(jose.SignatureAlgorithm(key.Algorithm))
			continue
		}
		for _, alg := range algsOfKey(key.Key) {
			add(alg)
		}
	}
	return algs
}

// algsOfKey names the signature algorithms one public key can verify.
//
// An elliptic curve names exactly one algorithm. An RSA modulus names none of
// the three, so all three are admitted: the JWS header picks one, and the
// signature must still verify under the key.
func algsOfKey(key any) []jose.SignatureAlgorithm {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return []jose.SignatureAlgorithm{jose.ES256}
		case elliptic.P384():
			return []jose.SignatureAlgorithm{jose.ES384}
		case elliptic.P521():
			return []jose.SignatureAlgorithm{jose.ES512}
		}
	}
	return nil
}
