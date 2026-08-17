/**
 * Server-only STATELESS custody of the console session and the pending auth flow.
 *
 * There is no server-side store — nothing keyed by an in-process `sid` Map, so
 * the console runs unchanged across N replicas (HA / horizontal scale) and
 * survives `next dev` route re-eval, with no Redis. Both the pending
 * authorization-code flow (state/verifier/nonce/returnTo) and the finished
 * session's token set (access/refresh) travel with the browser as **sealed**
 * cookies: a compact JWE (dir + A256GCM, jose) that is httpOnly + `__Host-` +
 * encrypted, so the tokens stay opaque outside this process (the same "browser
 * never holds a usable token" property the old in-memory store gave us).
 *
 * The id_token IS stored: console logout is RP-initiated, and the gateway's
 * end_session_endpoint takes it as the `id_token_hint` that names the session to
 * end. It is validated once at /auth/callback and never read for its claims
 * again.
 *
 * Key: AO_CONSOLE_COOKIE_SECRET (>= 32 chars). Unset in production is fatal
 * (fail closed); in development a fixed insecure key is used with a warning,
 * mirroring the gateway cipher's dev posture.
 *
 * Import only from server code (route handlers, middleware).
 */

import { EncryptJWT, jwtDecrypt } from "jose"

// __Host- prefix: requires Secure, Path=/, and no Domain — the strongest cookie
// scoping the platform offers (still accepted on http://localhost). The names are
// distinct from login-ui/portal-ui cookies so BFFs never collide on a shared host.
export const CONSOLE_SESSION_COOKIE = "__Host-ao_csid"
export const CONSOLE_FLOW_COOKIE = "__Host-ao_cflow"

/** Cookie attributes shared by every seal/clear. SameSite=Lax so the flow cookie
 *  rides the top-level GET redirect back from the gateway to /auth/callback. */
export const cookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "lax" as const,
  path: "/",
}

// A round-trip through the gateway authorize + login-ui should finish within this.
const FLOW_TTL = "10m"
// Hard cap on a sealed session's life regardless of the cookie being a session cookie.
const SESSION_TTL = "30d"

export interface Tokens {
  accessToken: string
  refreshToken?: string
  idToken?: string
  /** Absolute epoch-ms expiry of the access token. */
  expiresAt: number
}

/** The finished session: the token set plus the authenticated `sub`. */
export interface SessionTokens {
  sub: string
  accessToken: string
  refreshToken?: string
  /** Kept for the RP-initiated logout hint, never re-read for its claims. */
  idToken?: string
  expiresAt: number
}

/** A pending authorization-code flow, correlated to the callback by `state`. */
export interface PendingFlow {
  state: string
  verifier: string
  nonce: string
  /** Sanitized post-login return target (already open-redirect-guarded). */
  returnTo: string
}

let keyCache: Promise<Uint8Array> | null = null
let warned = false

// The AES-256 key is the SHA-256 digest of the configured secret (WebCrypto, so
// it runs in both the Node route handlers and the Edge middleware), NOT the raw
// first 32 bytes — a long-but-low-entropy secret still maps to a full-entropy
// 256-bit key. Async digest → cache the resolved-key Promise so only the first
// seal/open per process pays for it.
function key(): Promise<Uint8Array> {
  if (keyCache) return keyCache
  const secret = process.env.AO_CONSOLE_COOKIE_SECRET
  let material: string
  if (secret && secret.length >= 32) {
    material = secret
  } else if (process.env.NODE_ENV === "production") {
    throw new Error("AO_CONSOLE_COOKIE_SECRET (>= 32 chars) is required outside development")
  } else {
    if (!warned) {
      warned = true
      console.warn("console: AO_CONSOLE_COOKIE_SECRET unset — using an INSECURE dev key; set it before production")
    }
    material = "dev-only-insecure-console-cookie-key-0000"
  }
  keyCache = crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(material))
    .then((buf) => new Uint8Array(buf))
  return keyCache
}

async function seal(claims: Record<string, unknown>, ttl: string): Promise<string> {
  return new EncryptJWT(claims)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(ttl)
    .encrypt(await key())
}

/** Decrypts a sealed cookie; returns null for anything absent/expired/tampered.
 *  Algorithms are pinned to the seal side's dir + A256GCM — any other JWE header
 *  is rejected (defense-in-depth vs. algorithm confusion). */
async function open(value: string | undefined | null): Promise<Record<string, unknown> | null> {
  if (!value) return null
  try {
    const { payload } = await jwtDecrypt(value, await key(), {
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"],
    })
    return payload
  } catch {
    return null
  }
}

// ── pending flow ─────────────────────────────────────────────────────────────

export async function sealFlow(f: PendingFlow): Promise<string> {
  return seal({ ...f }, FLOW_TTL)
}

export async function openFlow(value: string | undefined | null): Promise<PendingFlow | null> {
  const p = await open(value)
  if (!p || typeof p.state !== "string" || typeof p.verifier !== "string") return null
  return { state: p.state, verifier: p.verifier, nonce: String(p.nonce ?? ""), returnTo: String(p.returnTo ?? "") }
}

// ── session ──────────────────────────────────────────────────────────────────

export async function sealSession(s: SessionTokens): Promise<string> {
  return seal({ ...s }, SESSION_TTL)
}

export async function openSession(value: string | undefined | null): Promise<SessionTokens | null> {
  const p = await open(value)
  if (!p || typeof p.accessToken !== "string" || typeof p.sub !== "string") return null
  return {
    sub: p.sub,
    accessToken: p.accessToken,
    refreshToken: typeof p.refreshToken === "string" ? p.refreshToken : undefined,
    idToken: typeof p.idToken === "string" ? p.idToken : undefined,
    expiresAt: typeof p.expiresAt === "number" ? p.expiresAt : 0,
  }
}
