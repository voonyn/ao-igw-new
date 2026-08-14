import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { sidFromIdToken } from "@/lib/server/session-sid"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/sessions/revoke-others — BFF proxy for "sign out others".
//
// Reads the caller's CURRENT session id (`sid`) from the server-held ID token —
// never from the browser — and calls the gateway bulk revoke
// (DELETE /api/v1/account/sessions?except=<sid>), which terminates every other
// session for the caller and spares the current one. When the ID token has no
// `sid`, `except` is omitted and the gateway signs out everywhere (the current
// session included) — a safe degradation, not a cross-user reach: termination is
// always scoped to the caller's own `sub`.
//
// It is a POST (not DELETE on the collection) so the browser fetch is a simple
// same-origin call; the SameSite=Lax cookie makes it CSRF-safe without a token.
export async function POST(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL("/api/v1/account/sessions", getOidcConfig().issuer)
  const sid = sidFromIdToken(next?.idToken)
  if (sid) url.searchParams.set("except", sid)
  try {
    const res = await fetch(url.toString(), {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    if (res.status === 200) {
      return await withRotation(NextResponse.json({ ok: true }), rotated, next)
    }
    // Pass the gateway's coarse code + status through, same mapping as password.
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account sessions revoke-others proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
