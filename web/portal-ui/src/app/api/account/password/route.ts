import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { sidFromIdToken } from "@/lib/server/session-sid"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/password — BFF proxy for self-service password change.
//
// Reads the user's access token server-side (keyed by the opaque `sid` cookie;
// the browser never sees it) and forwards `{ currentPassword, newPassword }` to
// the gateway's account API with a Bearer token. The gateway owns the actual
// change-password logic (verify current → validate new against policy → set),
// so this route only bridges the browser to it and passes the result back.
//
// The portal session cookie is SameSite=Lax, so a cross-site POST cannot carry
// it — this route is CSRF-safe without a separate token.
export async function POST(req: NextRequest) {
  // This route is excluded from the proxy/middleware, so it resolves (and, on a
  // refresh, persists) its own token instead of relying on a freshened cookie.
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    // No usable token server-side — the UI treats this as "sign in again".
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  let body: { currentPassword?: unknown; newPassword?: unknown }
  try {
    body = await req.json()
  } catch {
    return await withRotation(NextResponse.json({ error: "invalid_request" }, { status: 400 }), rotated, next)
  }

  // A successful change ends every other login session of this person. The
  // caller's own session is named here, from the server-held ID token, so the
  // device in front of the user survives the change. When the ID token carries no
  // `sid`, `except` is omitted and the gateway ends every session including this
  // one — a safe degradation, never a reach into another person's sessions.
  const url = new URL("/api/v1/account/password", getOidcConfig().issuer)
  const sid = sidFromIdToken(next?.idToken)
  if (sid) url.searchParams.set("except", sid)
  try {
    const res = await fetch(url.toString(), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ currentPassword: body.currentPassword, newPassword: body.newPassword }),
      cache: "no-store",
    })
    if (res.status === 200) {
      return await withRotation(NextResponse.json({ ok: true }), rotated, next)
    }
    // Pass the gateway's coarse error code + status straight through so the UI
    // can distinguish invalid_credentials / weak_password / invalid_request.
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account password proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

// Re-seals a rotated session onto the response so a refresh triggered here isn't
// lost (the refresh_token may have rotated at the gateway).
async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
