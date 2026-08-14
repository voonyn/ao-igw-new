import { NextRequest, NextResponse } from "next/server"

import { discover, getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE } from "@/lib/server/secure-cookie"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// Logout clears the server-side session + cookie, then drives OIDC RP-initiated
// logout: the browser is sent to the gateway end_session_endpoint with the
// id_token_hint and the registered post_logout_redirect_uri so the gateway also
// terminates the SSO login session named by the id_token's `sid`. This is one of
// the three self-service actions actually wired to the backend today.
//
// When no end_session endpoint / id_token is available it falls back to a local
// redirect to /auth/login. Accepts GET (link) and POST (form/fetch).
async function handle(req: NextRequest) {
  const cfg = getOidcConfig()
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const idToken = session?.idToken

  let target = new URL("/auth/login", cfg.portalUrl)
  try {
    const { end_session_endpoint } = await discover(cfg.issuer)
    if (end_session_endpoint && idToken) {
      const url = new URL(end_session_endpoint)
      url.searchParams.set("id_token_hint", idToken)
      url.searchParams.set("post_logout_redirect_uri", cfg.postLogoutRedirectUri)
      target = url
    }
  } catch (err) {
    console.error("portal: end_session discovery failed; local logout only", err)
  }

  const res = NextResponse.redirect(target)
  res.cookies.set(PORTAL_SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 })
  return res
}

export const GET = handle
export const POST = handle
