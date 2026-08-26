import { NextRequest, NextResponse } from "next/server"

import { resolveAccessToken } from "@/lib/server/admin-client"
import { cookieOptions, CONSOLE_SESSION_COOKIE, openSession, sealSession } from "@/lib/server/secure-cookie"

// Gate every console route behind a valid sealed session cookie, and keep its
// access token fresh. A request without a decryptable session is redirected to
// login. A session whose access token is near expiry is refreshed here (before the
// page renders and before the client-side /api/admin/* burst fires, so that burst
// runs with a fresh token); if the refresh fails the session is dead — clear the
// cookie and send to login.
//
// Next 16's `proxy` convention (the former `middleware`). The matcher excludes
// the auth routes, the no-access page, the BFF/api routes (they resolve tokens
// themselves), and Next's static assets so only console pages are gated.
export async function proxy(req: NextRequest) {
  const session = await openSession(req.cookies.get(CONSOLE_SESSION_COOKIE)?.value)
  if (!session) {
    return redirectToLogin(req)
  }

  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken || !next) {
    const res = redirectToLogin(req)
    res.cookies.set(CONSOLE_SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 })
    return res
  }

  // A refresh has to reach the render pass, not only the browser. Setting the
  // cookie on the response sends it back in Set-Cookie, but the request the page
  // renders from still carries the pre-refresh value, so a Server Component
  // would read a session one rotation behind and call the gateway with an access
  // token that just expired. Rewrite the request cookie header as well, which is
  // what `request.headers` on NextResponse.next forwards upstream.
  let sealed: string | null = null
  if (rotated) {
    sealed = await sealSession(next)
    req.cookies.set(CONSOLE_SESSION_COOKIE, sealed)
  }

  const headers = new Headers(req.headers)
  if (sealed) headers.set("cookie", req.cookies.toString())

  const res = NextResponse.next({ request: { headers } })
  if (sealed) res.cookies.set(CONSOLE_SESSION_COOKIE, sealed, cookieOptions)
  return res
}

function redirectToLogin(req: NextRequest): NextResponse {
  // Anchor to the canonical console origin (AO_CONSOLE_URL) so the redirect
  // survives a TLS-terminating reverse proxy; fall back to the request origin.
  const base = process.env.AO_CONSOLE_URL || req.nextUrl.origin
  const login = new URL("/auth/login", base)
  login.searchParams.set("returnTo", req.nextUrl.pathname + req.nextUrl.search)
  return NextResponse.redirect(login)
}

export const config = {
  matcher: ["/((?!auth|no-access|api|_next/static|_next/image|favicon.ico).*)"],
}
