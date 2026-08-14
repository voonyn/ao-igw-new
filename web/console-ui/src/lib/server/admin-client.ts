/**
 * Server-only client for the gateway console-admin API (stateless BFF).
 *
 * `resolveAccessToken` takes the decrypted session (from the sealed cookie) and
 * returns a non-expired access token, refreshing via the refresh_token grant
 * (with rotation) when it is within the expiry skew. A refresh MUTATES the
 * session, so the resolved session + a `rotated` flag come back too — the caller
 * (a route handler / middleware that owns a response) must re-seal it onto the
 * cookie. `adminFetch`/`adminMutate` then attach the resolved token as a bearer
 * to `/api/v1/admin/*`; the browser never receives it.
 */

import { getOidcConfig } from "./oidc-config"
import { refreshTokens } from "./oidc"
import type { SessionTokens } from "./secure-cookie"

// Refresh a little early so a request never races the access-token expiry.
const EXPIRY_SKEW_MS = 30 * 1000

export interface Resolved {
  /** A usable access token, or null when the session is dead (refresh failed). */
  accessToken: string | null
  /** The session to persist — rotated when `rotated`, otherwise the input. */
  session: SessionTokens | null
  /** True when tokens were refreshed and the caller must re-seal the cookie. */
  rotated: boolean
}

export async function resolveAccessToken(session: SessionTokens | null): Promise<Resolved> {
  if (!session) return { accessToken: null, session: null, rotated: false }

  if (Date.now() < session.expiresAt - EXPIRY_SKEW_MS) {
    return { accessToken: session.accessToken, session, rotated: false }
  }
  if (!session.refreshToken) {
    // No refresh available; let the gateway reject if the token is stale.
    return { accessToken: session.accessToken, session, rotated: false }
  }
  try {
    // ponytail: parallel /api/admin/* calls can each hit this after expiry and
    // race a rotating refresh_token (losers 401 → the client re-logs). A lock
    // would need the shared state we deliberately drop for HA; the middleware
    // refreshes on each page nav so the common burst runs with a fresh token.
    const rotated = await refreshTokens(session.refreshToken)
    const next: SessionTokens = {
      sub: session.sub,
      accessToken: rotated.accessToken,
      refreshToken: rotated.refreshToken,
      expiresAt: rotated.expiresAt,
    }
    return { accessToken: next.accessToken, session: next, rotated: true }
  } catch {
    return { accessToken: null, session: null, rotated: false }
  }
}

/**
 * Proxies a GET to `/api/v1/admin{path}` with `accessToken` attached as a bearer.
 * Returns 401 (no body) when no usable token was resolved.
 */
export async function adminFetch(accessToken: string | null, path: string): Promise<Response> {
  if (!accessToken) return unauthenticated()
  const { adminApiBase } = getOidcConfig()
  return fetch(`${adminApiBase}/api/v1/admin${path}`, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    cache: "no-store",
  })
}

/**
 * Proxies a mutation (POST/PUT/PATCH/DELETE) to `/api/v1/admin{path}` with the
 * bearer attached and the JSON body forwarded verbatim. Returns 401 (no body)
 * when no usable token was resolved. The gateway enforces the IAM_OWNER gate and
 * validation; this helper only attaches the token.
 */
export async function adminMutate(
  accessToken: string | null,
  path: string,
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  body: string | null,
): Promise<Response> {
  if (!accessToken) return unauthenticated()
  const { adminApiBase } = getOidcConfig()
  return fetch(`${adminApiBase}/api/v1/admin${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      ...(body != null ? { "Content-Type": "application/json" } : {}),
    },
    body: body ?? undefined,
    cache: "no-store",
  })
}

function unauthenticated(): Response {
  return new Response(JSON.stringify({ error: "unauthenticated" }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  })
}
