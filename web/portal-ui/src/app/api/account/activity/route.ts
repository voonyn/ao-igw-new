import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// GET /api/account/activity — BFF proxy for the caller's own activity feed.
//
// Forwards the user's access token server-side (keyed by the sealed cookie; the
// browser never sees it) to the gateway account API, which scopes the feed to the
// token `sub` — the BFF passes no actor and could not widen it if it tried.
// `page` and `limit` ride through verbatim: the feed pages by offset, like every
// other list of this deployment, and the gateway clamps both.
export async function GET(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    // No usable token server-side — the UI treats this as "sign in again".
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL("/api/v1/account/activity", getOidcConfig().issuer)
  for (const key of ["limit", "page"]) {
    const value = req.nextUrl.searchParams.get(key)
    if (value) url.searchParams.set(key, value)
  }
  try {
    const res = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    if (res.status === 200) {
      // The gateway answers this deployment's one envelope,
      // `{code, status, message, data, meta}`. The page is `data` and the count
      // of the whole feed is `meta.total`; anything else on the wire is a shape
      // the view cannot render, so it degrades to an empty page rather than to a
      // crash.
      const body = await res.json().catch(() => null)
      const events = Array.isArray(body?.data) ? body.data : []
      const total = typeof body?.meta?.total === "number" ? body.meta.total : 0
      return await withRotation(NextResponse.json({ events, total }), rotated, next)
    }
    // Relay the gateway's status + body as-is so the view can distinguish
    // unauthorized (re-login), rate_limited (wait) and invalid_request (a page
    // the gateway refused) exactly as the sessions route does.
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account activity proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

// Re-seals a rotated session onto the response so a refresh triggered here isn't
// lost (the refresh_token may have rotated at the gateway).
async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
