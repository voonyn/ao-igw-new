import { NextRequest, NextResponse } from "next/server"

import { adminFetch } from "@/lib/server/admin-client"
import { exchangeCode, validateIdToken } from "@/lib/server/oidc"
import { getOidcConfig } from "@/lib/server/oidc-config"
import { DEFAULT_LANDING } from "@/lib/server/redirect"
import {
  cookieOptions,
  CONSOLE_FLOW_COOKIE,
  CONSOLE_SESSION_COOKIE,
  openFlow,
  sealSession,
} from "@/lib/server/secure-cookie"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// This URL is the bootstrap-registered redirect URI: `{ConsoleURL}/auth/callback`.
const NO_ACCESS = "/no-access"

// Self-redirects are anchored to the canonical console origin (AO_CONSOLE_URL),
// not req.nextUrl.origin — behind a TLS-terminating reverse proxy the latter is
// the internal host (e.g. localhost:3002), which would leak into the redirect.
function consoleURL(path: string): URL {
  return new URL(path, getOidcConfig().consoleUrl)
}

// On any auth failure, land on the terminal /no-access page (never /auth/login,
// which would re-enter the flow and loop) and clear the single-use flow cookie.
function fail(error: string) {
  const url = consoleURL(NO_ACCESS)
  url.searchParams.set("error", error)
  const res = NextResponse.redirect(url)
  res.cookies.set(CONSOLE_FLOW_COOKIE, "", { ...cookieOptions, maxAge: 0 })
  return res
}

// GET /auth/callback — finish the authorization-code flow.
//
// Reads the sealed pending-flow cookie (CSRF/replay: its `state` must match the
// query `state`), exchanges the code with the stored PKCE verifier, validates the
// id_token (iss/aud/nonce/exp), then makes the membership decision via /me using
// the freshly-exchanged token: 403 ⇒ no session + no-access page; success ⇒ seal
// the session cookie and land.
export async function GET(req: NextRequest) {
  const params = req.nextUrl.searchParams
  const oauthError = params.get("error")
  if (oauthError) {
    return fail(oauthError)
  }

  const code = params.get("code")
  const state = params.get("state")
  if (!code || !state) {
    return fail("missing_code_or_state")
  }

  // The flow travels with the browser (sealed cookie); its state must match.
  const flow = await openFlow(req.cookies.get(CONSOLE_FLOW_COOKIE)?.value)
  if (!flow || flow.state !== state) {
    return fail("invalid_state")
  }

  let tokens
  try {
    tokens = await exchangeCode(code, flow.verifier)
  } catch (err) {
    console.error("console: token exchange failed", err)
    return fail("exchange_failed")
  }
  if (!tokens.idToken) {
    return fail("missing_id_token")
  }

  let sub: string
  try {
    sub = await validateIdToken(tokens.idToken, flow.nonce)
  } catch (err) {
    console.error("console: id_token validation failed", err)
    return fail("idtoken_invalid")
  }

  // Membership-driven access decision via /me, using the just-exchanged token.
  const meRes = await adminFetch(tokens.accessToken, "/me")
  if (meRes.status === 403) {
    return fail("not_a_console_user")
  }
  if (!meRes.ok) {
    return fail("me_unavailable")
  }

  // Finalize: land the user, hand the browser the sealed session, and drop the
  // now-consumed flow cookie. The id_token stays in the seal, because the
  // RP-initiated logout presents it to the gateway as the id_token_hint.
  const res = NextResponse.redirect(consoleURL(flow.returnTo || DEFAULT_LANDING))
  res.cookies.set(
    CONSOLE_SESSION_COOKIE,
    await sealSession({
      sub,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      idToken: tokens.idToken,
      expiresAt: tokens.expiresAt,
    }),
    cookieOptions,
  )
  res.cookies.set(CONSOLE_FLOW_COOKIE, "", { ...cookieOptions, maxAge: 0 })
  return res
}
