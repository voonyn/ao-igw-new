import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { sidFromIdToken } from "@/lib/server/session-sid"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// GET /api/account/sessions — BFF proxy for the self-service session list.
//
// Forwards the user's access token server-side (keyed by the sealed cookie; the
// browser never sees it) to the gateway account API, and adds the caller's
// CURRENT session id read from the ID token the BFF holds in the same cookie.
// The access token carries no `sid`, and the browser must not choose which
// session is "current" for a security decision — so `currentSid` comes only from
// the server-side ID token. Returns `{ sessions, currentSid }`; currentSid is ""
// when the ID token lacks `sid` (the view then omits the "This device" flag).
export async function GET(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    // No usable token server-side — the UI treats this as "sign in again".
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL("/api/v1/account/sessions", getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    if (res.status === 200) {
      const sessions = await res.json().catch(() => [])
      const currentSid = sidFromIdToken(next?.idToken)
      return await withRotation(NextResponse.json({ sessions, currentSid }), rotated, next)
    }
    // Pass the gateway's coarse code + status through so the view can distinguish
    // unauthorized (re-login) / rate_limited (wait), like the password route.
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account sessions list proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

// Re-seals a rotated session onto the response so a refresh triggered here isn't
// lost (the refresh_token may have rotated at the gateway).
async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
