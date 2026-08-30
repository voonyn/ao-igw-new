package middlewares

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// ErrIssuerMismatch reports that the resolved host is not the host the tenant's
// issuer names. Every token that tenant signs carries the issuer, so answering
// on another host would sign tokens nobody can verify against this address.
var ErrIssuerMismatch = errors.New("host does not match the tenant issuer")

// tenantLocalsKey names the resolved tenant in the request locals.
const tenantLocalsKey = "ao_tenant"

// TenantContext is what one request knows about its tenant: the tenant id every
// store method takes, the protocol settings the provider is built from, and the
// host that resolved the two.
//
// Host is the verified host, after the trusted header and the proxy rules were
// applied. The passkey ceremonies derive their RP ID from its registrable
// domain, so they bind a credential to the same host that already names the
// tenant.
type TenantContext struct {
	TenantID string
	Config   oidc.ProviderConfig
	Host     string
}

// Lookup maps a bare host to its tenant. It returns tenant.ErrDomainNotFound or
// oidc.ErrProviderConfigNotFound when no tenant serves the host.
type Lookup func(ctx context.Context, host string) (TenantContext, error)

// DBLookup reads the tenant of a host from the database: the domain names the
// tenant, and the tenant names its provider config.
func DBLookup(domains *tenant.Repository, configs *oidc.ProviderRepository) Lookup {
	return func(ctx context.Context, host string) (TenantContext, error) {
		tenantID, err := domains.TenantIDByDomain(ctx, host)
		if err != nil {
			return TenantContext{}, err
		}
		cfg, err := configs.FindByTenant(ctx, tenantID)
		if err != nil {
			return TenantContext{}, err
		}
		return TenantContext{TenantID: tenantID, Config: cfg}, nil
	}
}

// Tenant resolves the request host to a tenant and stores it on the request.
// The host comes from trustedHeader when that name is configured, and from the
// verified request host otherwise. Only set trustedHeader when a trusted proxy
// injects the header, because it bypasses the host check.
//
// A host no tenant owns gives 404, and so does a host the tenant's issuer does
// not name. The two answer alike, so the response never says which tenants exist.
func Tenant(lookup Lookup, trustedHeader string, log logger.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		host := hostFromRequest(c, trustedHeader)

		tc, err := lookup(c.Context(), host)
		if err != nil {
			if errors.Is(err, tenant.ErrDomainNotFound) || errors.Is(err, oidc.ErrProviderConfigNotFound) {
				log.Warn("no tenant serves the host", logger.String("host", host))
				return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
			}
			log.Error("resolve tenant", logger.String("host", host), logger.Err(err))
			return err
		}

		if err := verifyIssuerHost(tc.Config.Issuer, host); err != nil {
			log.Error("tenant issuer does not match the host",
				logger.String("tenant_id", tc.TenantID),
				logger.String("host", host),
				logger.Err(err))
			return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
		}

		tc.Host = host
		c.Locals(tenantLocalsKey, tc)
		return c.Next()
	}
}

// TenantFrom returns the tenant the Tenant middleware resolved for the request.
func TenantFrom(c fiber.Ctx) (TenantContext, bool) {
	tc, ok := c.Locals(tenantLocalsKey).(TenantContext)
	return tc, ok
}

// hostFromRequest picks the host the tenant resolves from. The trusted header
// wins when it is configured and present, so a local developer can reach a
// tenant that answers on another name.
func hostFromRequest(c fiber.Ctx, trustedHeader string) string {
	if trustedHeader != "" {
		if host := normalizeHost(c.Get(trustedHeader)); host != "" {
			return host
		}
	}
	return normalizeHost(c.Host())
}

// normalizeHost reduces a host to the form tenant_domains stores: lowercased,
// no scheme, no path, no trailing dot, and the port kept.
func normalizeHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	if _, after, found := strings.Cut(host, "://"); found {
		host = after
	}
	host, _, _ = strings.Cut(host, "/")
	return strings.TrimSuffix(host, ".")
}

// verifyIssuerHost rejects a host the tenant's issuer does not name.
func verifyIssuerHost(issuer, host string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: issuer %q names no host", ErrIssuerMismatch, issuer)
	}
	if !strings.EqualFold(u.Host, host) {
		return fmt.Errorf("%w: host %q, issuer host %q", ErrIssuerMismatch, host, u.Host)
	}
	return nil
}
