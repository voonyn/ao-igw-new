/**
 * Server-only PKCE + random-value helpers for the authorization-code flow.
 * Uses the Web Crypto API (available in the Next.js Node runtime); secrets never
 * leave the server.
 */

/** base64url without padding. */
function base64url(bytes: Uint8Array): string {
  let bin = ""
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** A URL-safe random token of `bytes` entropy (default 32). */
export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return base64url(buf)
}

/** A fresh PKCE code_verifier (RFC 7636 — 43-128 chars of unreserved set). */
export function createVerifier(): string {
  return randomToken(32) // ~43 base64url chars
}

/** The S256 code_challenge for a verifier. */
export async function challengeS256(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const digest = await crypto.subtle.digest("SHA-256", data)
  return base64url(new Uint8Array(digest))
}
