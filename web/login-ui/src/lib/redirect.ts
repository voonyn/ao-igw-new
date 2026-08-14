/**
 * Server-only helper that validates a post-login `redirect_uri` before the
 * browser is ever sent to it — closing the open-redirect hole an attacker-crafted
 * `?redirect_uri=` link would otherwise open.
 *
 * A target is accepted when it is:
 *   - a same-origin relative path ("/home"), or
 *   - an absolute http(s) URL whose host is the login-ui's own host or appears
 *     in AO_POST_LOGIN_ALLOWED_ORIGINS (comma-separated origins or bare hosts).
 *
 * Anything else (other schemes, protocol-relative "//evil", off-allowlist
 * hosts, malformed input) collapses to "" so callers fall back to the signed-in
 * screen rather than redirecting somewhere untrusted.
 *
 * Import this only from server code: it reads process.env, and the verdict must
 * not be re-derived in the browser where the query string is attacker-controlled.
 */
export function sanitizeRedirectUri(raw: string | undefined, host: string): string {
  if (!raw || !host) return ""

  let target: URL
  try {
    // Resolve against the login-ui origin so relative paths keep their host and
    // protocol-relative "//evil" resolves to its real host for the check below.
    target = new URL(raw, `https://${host}`)
  } catch {
    return ""
  }

  if (target.protocol !== "https:" && target.protocol !== "http:") return ""

  const allowed = new Set<string>([host.toLowerCase()])
  for (const entry of (process.env.AO_POST_LOGIN_ALLOWED_ORIGINS ?? "").split(",")) {
    const trimmed = entry.trim()
    if (!trimmed) continue
    try {
      allowed.add(new URL(trimmed).host.toLowerCase())
    } catch {
      allowed.add(trimmed.toLowerCase()) // bare host entry (no scheme)
    }
  }

  if (!allowed.has(target.host.toLowerCase())) return ""

  // Preserve a relative target as-given; otherwise hand back the normalized URL.
  return raw.startsWith("/") && !raw.startsWith("//") ? raw : target.toString()
}
