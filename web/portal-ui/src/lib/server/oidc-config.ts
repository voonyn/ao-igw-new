/**
 * Server-only OIDC relying-party configuration + discovery for portal-ui.
 *
 * The portal authenticates against the gateway as the bootstrap-seeded
 * `portal-ui` public SPA client (authorization_code + PKCE, token_authn=none).
 * Bootstrap mints a random client_id and prints it once, so the portal reads it
 * from the environment (AO_OIDC_CLIENT_ID).
 *
 * Unlike console-ui there is NO admin resource indicator and NO admin API base.
 * The portal DOES send the account resource indicator (AccountAudience) at
 * /authorize so its access token is accepted by the gateway's self-service
 * account API (/api/v1/account/*); beyond that it uses the OIDC protocol
 * endpoints reachable with the user's own token — /authorize, /token, /userinfo
 * and the end_session (logout) endpoint.
 *
 * Import only from route handlers / server components — this reads process.env
 * and must never reach the browser bundle.
 */

export interface PortalOidcConfig {
  /** Token issuer; also the discovery base (`{issuer}/.well-known/openid-configuration`). */
  issuer: string
  /** The bootstrap-printed `portal-ui` client id. */
  clientId: string
  /** Portal origin, used to build the registered redirect + post-logout URIs and the open-redirect allowlist. */
  portalUrl: string
  /** Must equal the bootstrap-registered redirect URI `{PortalURL}/auth/callback`. */
  redirectUri: string
  /** Registered post-logout redirect target `{PortalURL}/`. */
  postLogoutRedirectUri: string
  /** Scopes requested at authorize; `offline_access` yields a refresh token. */
  scope: string
  /**
   * RFC 8707 resource indicator sent at `/authorize`, so the access token's
   * `aud` designates the gateway self-service account API (`/api/v1/account`).
   * The account resource server rejects tokens lacking it. MUST match the
   * gateway's `oidc.AccountAudience` (Go). Bound to AO_OIDC_ACCOUNT_RESOURCE.
   */
  accountResource: string
}

/** Reads the portal RP configuration from the environment (dev defaults match BOOTSTRAP.md). */
export function getOidcConfig(): PortalOidcConfig {
  const issuer = trimSlash(process.env.AO_OIDC_ISSUER ?? "http://auth.localhost:8080")
  const portalUrl = trimSlash(process.env.AO_PORTAL_URL ?? "http://localhost:3001")
  const clientId = process.env.AO_OIDC_CLIENT_ID ?? ""
  return {
    issuer,
    clientId,
    portalUrl,
    redirectUri: `${portalUrl}/auth/callback`,
    postLogoutRedirectUri: `${portalUrl}/`,
    scope: "openid profile email offline_access",
    // Keep in sync with oidc.AccountAudience in the Go gateway.
    accountResource: process.env.AO_OIDC_ACCOUNT_RESOURCE ?? "urn:alphaomega:account-api",
  }
}

export interface DiscoveryDocument {
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string
  end_session_endpoint?: string
}

// Discovery rarely changes; cache it per-process so each auth hop is one fetch.
let discoveryCache: { issuer: string; doc: DiscoveryDocument; fetchedAt: number } | null = null
const DISCOVERY_TTL_MS = 5 * 60 * 1000

/**
 * Fetches (and caches) the gateway's OpenID discovery document so the RP never
 * hardcodes endpoint paths. The gateway resolves the tenant from the request
 * Host, which matches the issuer host server-side.
 */
export async function discover(issuer: string): Promise<DiscoveryDocument> {
  const now = Date.now()
  if (discoveryCache && discoveryCache.issuer === issuer && now - discoveryCache.fetchedAt < DISCOVERY_TTL_MS) {
    return discoveryCache.doc
  }
  const res = await fetch(`${issuer}/.well-known/openid-configuration`, { cache: "no-store" })
  if (!res.ok) {
    throw new Error(`oidc discovery failed: ${res.status}`)
  }
  const doc = (await res.json()) as DiscoveryDocument
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error("oidc discovery missing required endpoints")
  }
  discoveryCache = { issuer, doc, fetchedAt: now }
  return doc
}

function trimSlash(s: string): string {
  return s.replace(/\/+$/, "")
}
