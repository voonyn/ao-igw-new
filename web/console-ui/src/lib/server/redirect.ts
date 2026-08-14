/**
 * Server-only open-redirect guard for the post-login return target.
 *
 * Mirrors login-ui's redirect guard. A target is accepted only when it is a
 * same-origin relative path ("/overview"); any absolute/scheme/protocol-relative
 * input collapses to the default landing route. The console never returns the
 * browser to an off-origin URL after login.
 */

/** Default console landing route. */
export const DEFAULT_LANDING = "/overview"

/**
 * Returns a safe relative return target, or DEFAULT_LANDING for anything that is
 * not a plain same-origin path. Rejects "//evil", "https://evil", "\\evil", and
 * non-path inputs.
 */
export function sanitizeReturnTo(raw: string | undefined | null): string {
  if (!raw) return DEFAULT_LANDING
  // Must be an absolute path, not protocol-relative ("//") or a backslash trick.
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return DEFAULT_LANDING
  // Reject anything that parses with a host (e.g. embedded scheme) by resolving
  // against a throwaway origin and confirming it stayed same-origin.
  try {
    const u = new URL(raw, "https://console.invalid")
    if (u.origin !== "https://console.invalid") return DEFAULT_LANDING
    return u.pathname + u.search + u.hash
  } catch {
    return DEFAULT_LANDING
  }
}
