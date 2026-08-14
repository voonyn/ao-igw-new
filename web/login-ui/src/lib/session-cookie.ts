/**
 * Server-only helpers for the single login-session cookie. Next.js (this BFF)
 * exclusively owns this cookie; the Go gateway never reads or sets it.
 *
 * These helpers are pure (no framework imports) so route handlers can apply the
 * name/value/options to a NextResponse. The module is server-only by its import
 * graph — only route handlers and server components import it, never client
 * components — so the session token never reaches the browser bundle.
 */

// __Host- prefix: requires Secure, Path=/, and no Domain attribute — the
// strongest cookie scoping the platform offers.
export const SESSION_COOKIE = "__Host-ao_sid"

// Payload version. v1 carries a single account; the format is versioned so a
// future multi-account list can be introduced without ambiguity.
const VERSION = "v1"

export type SessionCookie = { sid: string; token: string }

/**
 * Parses `v1.{sid}.{token}`. Returns null for anything malformed or a different
 * version. The token is base64url (no dots) and the sid is a UUID (no dots), so
 * an exact 3-part split is unambiguous.
 */
export function parseSessionCookie(value: string | undefined | null): SessionCookie | null {
  if (!value) return null
  const parts = value.split(".")
  if (parts.length !== 3 || parts[0] !== VERSION) return null
  const [, sid, token] = parts
  if (!sid || !token) return null
  return { sid, token }
}

/** Serializes the versioned payload. */
export function serializeSessionCookie(sid: string, token: string): string {
  return `${VERSION}.${sid}.${token}`
}

/** Cookie attributes shared by set/rotate/clear. */
export const sessionCookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "lax" as const,
  path: "/",
}
