import { NextRequest, NextResponse } from "next/server"

import { discover, getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, CONSOLE_SESSION_COOKIE, openSession } from "@/lib/server/secure-cookie"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0).
//
// The console clears its own sealed session cookie and hands the browser to the
// gateway's end_session_endpoint, which ends the SSO session there too. Without
// that second half, a sign-out returns to a gateway that still knows the person,
// and the next sign-in never asks for a password.
//
// The hint is the id_token the callback sealed. post_logout_redirect_uri must be
// the console origin with a trailing slash: bootstrap registers exactly that
// value, and the protocol engine refuses any other.
//
// Accepts GET (link) and POST (form/fetch).
async function handle(req: NextRequest) {
  const { issuer, consoleUrl } = getOidcConfig()
  const session = await openSession(req.cookies.get(CONSOLE_SESSION_COOKIE)?.value)

  const res = NextResponse.redirect(await endSession(issuer, consoleUrl, session?.idToken))
  res.cookies.set(CONSOLE_SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 })
  return res
}

// endSession builds the gateway logout URL. Three cases fall back to the local
// login page: a session that carries no id_token, a gateway that publishes no
// end_session_endpoint, and a discovery read that fails. The cookie is cleared
// in every one of them, so the console session ends either way.
//
// A session with no id_token cannot end the gateway session at all. The gateway
// refuses a logout request that names no hint, because such a request says
// nothing about who is signing out. See internal/api/oidc/logout.go.
async function endSession(issuer: string, consoleUrl: string, idToken?: string): Promise<URL> {
  const local = new URL("/auth/login", consoleUrl)
  if (!idToken) {
    return local
  }

  let endpoint: string | undefined
  try {
    endpoint = (await discover(issuer)).end_session_endpoint
  } catch (err) {
    console.error("console: discovery failed during logout", err)
    return local
  }
  if (!endpoint) {
    return local
  }

  const url = new URL(endpoint)
  url.searchParams.set("id_token_hint", idToken)
  url.searchParams.set("post_logout_redirect_uri", `${consoleUrl}/`)
  return url
}

export const GET = handle
export const POST = handle
