import { NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, CONSOLE_SESSION_COOKIE } from "@/lib/server/secure-cookie"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// Logout clears the sealed console session cookie, then sends the browser to
// login. Phase 1 is local-only — the gateway SSO session is governed by
// add-sso-login-sessions. Accepts GET (link) and POST (form/fetch). The redirect
// is anchored to AO_CONSOLE_URL so it stays correct behind a proxy.
function handle() {
  const res = NextResponse.redirect(new URL("/auth/login", getOidcConfig().consoleUrl))
  res.cookies.set(CONSOLE_SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 })
  return res
}

export const GET = handle
export const POST = handle
