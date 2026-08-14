import { NextRequest, NextResponse } from "next/server"

import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Gate every portal route behind a valid sealed session cookie, and keep its
// access token fresh. A request without a decryptable session is redirected to
// login. A session whose access token is near expiry is refreshed here (the one
// place before the page renders that owns a response and can re-seal the cookie);
// if the refresh fails the session is dead — clear the cookie and send to login.
//
// Next 16's `proxy` convention (the former `middleware`). The matcher excludes
// the auth routes, the BFF/api routes (they resolve tokens themselves), and
// Next's static assets so only portal pages are gated.
export async function proxy(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  if (!session) {
    return redirectToLogin(req)
  }

  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken || !next) {
    const res = redirectToLogin(req)
    res.cookies.set(PORTAL_SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 })
    return res
  }

  const res = NextResponse.next()
  if (rotated) {
    // ponytail: parallel tabs can race a rotating refresh_token here; last writer
    // wins and the loser re-logs. A per-session lock would need the shared state
    // we deliberately don't keep — acceptable for a self-service portal.
    res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  }
  return res
}

function redirectToLogin(req: NextRequest): NextResponse {
  // Anchor to the canonical portal origin (AO_PORTAL_URL) so the redirect
  // survives a TLS-terminating reverse proxy; fall back to the request origin.
  const base = process.env.AO_PORTAL_URL || req.nextUrl.origin
  const login = new URL("/auth/login", base)
  login.searchParams.set("returnTo", req.nextUrl.pathname + req.nextUrl.search)
  return NextResponse.redirect(login)
}

export const config = {
  matcher: ["/((?!auth|api|_next/static|_next/image|favicon.ico).*)"],
}
