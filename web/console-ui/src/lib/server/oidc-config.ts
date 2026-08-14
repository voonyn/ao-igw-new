/**
 * Server-only OIDC relying-party configuration + discovery.
 *
 * The console authenticates against the gateway as the bootstrap-seeded
 * `console-ui` public SPA client (authorization_code + PKCE, token_authn=none).
 * There is no fixed `a-console-web` client id: bootstrap mints a random
 * client_id and prints it once, so the console reads it from the environment.
 *
 * Import only from route handlers / server components — this reads process.env
 * and must never reach the browser bundle. The module is server-only by its
 * import graph (no client component imports anything under lib/server).
 */

export interface ConsoleOidcConfig {
  /** Token issuer; also the discovery base (`{issuer}/.well-known/openid-configuration`). */
  issuer: string
  /** The bootstrap-printed `console-ui` client id. */
  clientId: string
  /** Gateway base for `/api/v1/admin/*` reads. */
  adminApiBase: string
  /** Console origin, used to build the registered redirect URI + open-redirect allowlist. */
  consoleUrl: string
  /** Must equal the bootstrap-registered redirect URI `{ConsoleURL}/auth/callback`. */
  redirectUri: string
  /** Scopes requested at authorize; `offline_access` yields a refresh token. */
  scope: string
  /**
   * RFC 8707 resource indicator sent at `/authorize`, so the access token's
   * `aud` designates the gateway admin API. The admin resource server rejects
   * tokens lacking it, so an ordinary tenant token cannot reach the admin API.
   * MUST match the gateway's `oidc.AdminAudience` (Go). Bound to
   * AO_OIDC_ADMIN_RESOURCE.
   */
  adminResource: string
}

/** Reads the console RP configuration from the environment (dev defaults match BOOTSTRAP.md). */
export function getOidcConfig(): ConsoleOidcConfig {
  const issuer = trimSlash(process.env.AO_OIDC_ISSUER ?? "http://auth.localhost:8080")
  const consoleUrl = trimSlash(process.env.AO_CONSOLE_URL ?? "http://localhost:3002")
  const clientId = process.env.AO_OIDC_CLIENT_ID ?? ""
  const adminApiBase = trimSlash(process.env.AO_ADMIN_API_BASE ?? issuer)
  return {
    issuer,
    clientId,
    adminApiBase,
    consoleUrl,
    redirectUri: `${consoleUrl}/auth/callback`,
    scope: "openid profile email offline_access",
    // Keep in sync with oidc.AdminAudience in the Go gateway.
    adminResource: process.env.AO_OIDC_ADMIN_RESOURCE ?? "urn:alphaomega:admin-api",
  }
}

export interface DiscoveryDocument {
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
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
