/**
 * Server-only OIDC code-exchange, refresh, and id_token validation.
 *
 * The console is a public client (token_authn_method=none): the token requests
 * carry `client_id` + PKCE, no client secret. id_token signatures are verified
 * against the gateway JWKS via `jose`; issuer/audience/expiry are enforced by
 * `jwtVerify` and the nonce is checked explicitly.
 */

import { createRemoteJWKSet, jwtVerify } from "jose"

import { discover, getOidcConfig } from "./oidc-config"
import type { Tokens } from "./secure-cookie"

interface TokenResponse {
  access_token: string
  refresh_token?: string
  id_token?: string
  token_type?: string
  expires_in?: number
  error?: string
  error_description?: string
}

/** Maps a token response onto the stored token set with an absolute expiry. */
function toTokens(t: TokenResponse): Tokens {
  return {
    accessToken: t.access_token,
    refreshToken: t.refresh_token,
    idToken: t.id_token,
    // default to a conservative 5 min if the AS omits expires_in
    expiresAt: Date.now() + (t.expires_in ?? 300) * 1000,
  }
}

/** Exchanges an authorization code for tokens using the stored PKCE verifier. */
export async function exchangeCode(code: string, codeVerifier: string): Promise<Tokens> {
  const cfg = getOidcConfig()
  const { token_endpoint } = await discover(cfg.issuer)
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    code_verifier: codeVerifier,
  })
  const res = await fetch(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body,
    cache: "no-store",
  })
  const data = (await res.json()) as TokenResponse
  if (!res.ok || !data.access_token) {
    throw new Error(`token exchange failed: ${res.status} ${data.error ?? ""}`.trim())
  }
  return toTokens(data)
}

/** Refreshes tokens via the refresh_token grant (server-side rotation). */
export async function refreshTokens(refreshToken: string): Promise<Tokens> {
  const cfg = getOidcConfig()
  const { token_endpoint } = await discover(cfg.issuer)
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: cfg.clientId,
  })
  const res = await fetch(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body,
    cache: "no-store",
  })
  const data = (await res.json()) as TokenResponse
  if (!res.ok || !data.access_token) {
    throw new Error(`token refresh failed: ${res.status} ${data.error ?? ""}`.trim())
  }
  // A non-rotating AS may omit refresh_token; keep the prior one in that case.
  const tokens = toTokens(data)
  if (!tokens.refreshToken) tokens.refreshToken = refreshToken
  return tokens
}

// JWKS is cached by jose across calls; keyed by jwks_uri so a re-discovery reuses it.
let jwksCache: { uri: string; jwks: ReturnType<typeof createRemoteJWKSet> } | null = null

function jwksFor(uri: string) {
  if (!jwksCache || jwksCache.uri !== uri) {
    jwksCache = { uri, jwks: createRemoteJWKSet(new URL(uri)) }
  }
  return jwksCache.jwks
}

/**
 * Validates an id_token: signature against the gateway JWKS, plus issuer,
 * audience (== client_id), expiry (jwtVerify), and the nonce. Returns `sub`.
 */
export async function validateIdToken(idToken: string, expectedNonce: string): Promise<string> {
  const cfg = getOidcConfig()
  const { jwks_uri } = await discover(cfg.issuer)
  const { payload } = await jwtVerify(idToken, jwksFor(jwks_uri), {
    issuer: cfg.issuer,
    audience: cfg.clientId,
  })
  if (!payload.nonce || payload.nonce !== expectedNonce) {
    throw new Error("id_token nonce mismatch")
  }
  if (typeof payload.sub !== "string" || !payload.sub) {
    throw new Error("id_token missing sub")
  }
  return payload.sub
}
