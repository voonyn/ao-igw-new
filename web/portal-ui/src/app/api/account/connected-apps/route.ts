import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// GET /api/account/connected-apps — BFF proxy for the self-service connected-app
// list (the third-party OIDC clients the caller has consented to).
//
// Forwards the user's access token server-side (keyed by the sealed cookie; the
// browser never sees it). The BFF passes no subject and could not widen the
// result if it tried — the gateway scopes the listing to the token `sub`.
export async function GET(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    // No usable token server-side — the UI treats this as "sign in again".
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL("/api/v1/account/connected-apps", getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    // Status and body relay verbatim so the view can tell 401 (re-login) from 429
    // (back off) without the BFF inventing a second error vocabulary.
    const data = await res.json().catch(() => (res.status === 200 ? [] : { error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account connected-apps list proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

// Re-seals a rotated session onto the response so a refresh triggered here isn't
// lost (the refresh_token may have rotated at the gateway).
async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
