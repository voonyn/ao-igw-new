/**
 * Server-only access-token resolution for the stateless portal BFF.
 *
 * Takes the decrypted session (from the sealed cookie), returns a non-expired
 * access token, refreshing via the refresh_token grant (with rotation) when the
 * access token is within the expiry skew. Because a refresh MUTATES the session,
 * the resolved (possibly rotated) session is returned too — a caller that owns a
 * response (middleware, a route handler) must re-seal it onto the cookie so the
 * rotated refresh_token isn't lost. Server components can't set cookies, so they
 * read the token as-is; the middleware refreshes ahead of them.
 */

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
    const rotated = await refreshTokens(session.refreshToken)
    const next: SessionTokens = { sub: session.sub, ...rotated }
    return { accessToken: next.accessToken, session: next, rotated: true }
  } catch {
    return { accessToken: null, session: null, rotated: false }
  }
}
