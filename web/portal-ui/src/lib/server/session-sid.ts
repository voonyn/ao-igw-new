import { decodeJwt } from "jose"

/**
 * Reads the `sid` (session id) claim from the portal's stored ID token.
 *
 * The ID token was validated at callback and is held server-side (sealed
 * cookie), so this only DECODES it — no signature check — to learn which login
 * session is the caller's current one. The access token the account API validates
 * deliberately carries no `sid`, so this is the only server-side source of the
 * "current session" for flagging "This device" and for `except` on sign-out-others.
 *
 * Returns "" when the token is absent or unparseable, or the claim is missing —
 * callers then omit the current flag and fall back to sign-out-everywhere.
 */
export function sidFromIdToken(idToken: string | undefined): string {
  if (!idToken) return ""
  try {
    const claims = decodeJwt(idToken)
    return typeof claims.sid === "string" ? claims.sid : ""
  } catch {
    return ""
  }
}
