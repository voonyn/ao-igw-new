/**
 * Server-only fetch of the authenticated user's OIDC claims from /userinfo.
 *
 * This is the ONE self-service read the portal can make with the user's own
 * access token today: the gateway's userinfo endpoint returns the claims released
 * by the tenant's scope/claim-mapper config (name, given_name, family_name,
 * preferred_username, locale, email, email_verified, ...). Everything else the
 * portal shows has no self-service API yet and is rendered as "Not Wired".
 */

import { discover, getOidcConfig } from "./oidc-config"
import type { SessionTokens } from "./secure-cookie"

/** Standard OIDC claims the portal reads. All optional — depends on tenant config. */
export interface UserinfoClaims {
  sub?: string
  name?: string
  given_name?: string
  family_name?: string
  preferred_username?: string
  email?: string
  email_verified?: boolean
  locale?: string
  updated_at?: number
  [claim: string]: unknown
}

/**
 * Fetches the userinfo claims for the session, or null when unauthenticated or
 * the endpoint is unavailable. Never throws — a null result degrades the profile
 * to its placeholder values rather than failing the page.
 */
// Reads the token straight off the (middleware-freshened) session — a server
// component can't set cookies, so it never refreshes here.
export async function fetchUserinfo(session: SessionTokens | null): Promise<UserinfoClaims | null> {
  const token = session?.accessToken
  if (!token) return null
  try {
    const { userinfo_endpoint } = await discover(getOidcConfig().issuer)
    if (!userinfo_endpoint) return null
    const res = await fetch(userinfo_endpoint, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      cache: "no-store",
    })
    if (!res.ok) return null
    return (await res.json()) as UserinfoClaims
  } catch {
    return null
  }
}
