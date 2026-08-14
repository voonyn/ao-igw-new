import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/profile — BFF proxy for self-service profile update.
//
// Reads the user's access token server-side (keyed by the opaque `sid` cookie;
// the browser never sees it) and forwards the identity fields to the gateway's
// account API with a Bearer token. The gateway updates only the caller's own
// identity columns (name, display name, language) — contact fields are left
// untouched — so this route only bridges the browser to it and passes the
// result back.
//
// The portal session cookie is SameSite=Lax, so a cross-site POST cannot carry
// it — this route is CSRF-safe without a separate token. Mirrors the password
// route (/api/account/password).
export async function POST(req: NextRequest) {
  // This route is excluded from the proxy/middleware, so it resolves (and, on a
  // refresh, persists) its own token instead of relying on a freshened cookie.
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    // No usable token server-side — the UI treats this as "sign in again".
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  let body: { firstName?: unknown; lastName?: unknown; displayName?: unknown; locale?: unknown }
  try {
    body = await req.json()
  } catch {
    return await withRotation(NextResponse.json({ error: "invalid_request" }, { status: 400 }), rotated, next)
  }

  const url = new URL("/api/v1/account/profile", getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        firstName: body.firstName,
        lastName: body.lastName,
        displayName: body.displayName,
        locale: body.locale,
      }),
      cache: "no-store",
    })
    if (res.status === 200) {
      return await withRotation(NextResponse.json({ ok: true }), rotated, next)
    }
    // Pass the gateway's coarse error code + status straight through so the UI
    // can distinguish invalid_request / rate_limited / re-auth.
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account profile proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

// Re-seals a rotated session onto the response so a refresh triggered here isn't
// lost (the refresh_token may have rotated at the gateway).
async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
