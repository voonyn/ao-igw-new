/**
 * Server-only open-redirect guard for the post-login `returnTo`.
 *
 * Only same-origin absolute paths are allowed; anything with a scheme, host, or
 * protocol-relative prefix is rejected to the default landing.
 */

export const DEFAULT_LANDING = "/"

/** Returns a safe same-origin path, or DEFAULT_LANDING for anything suspicious. */
export function sanitizeReturnTo(raw: string | null | undefined): string {
  if (!raw) return DEFAULT_LANDING
  // Must be a root-relative path and not protocol-relative (`//host`).
  if (!raw.startsWith("/") || raw.startsWith("//")) return DEFAULT_LANDING
  if (raw.includes("://")) return DEFAULT_LANDING
  return raw
}
