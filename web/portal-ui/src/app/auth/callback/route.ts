import { NextRequest, NextResponse } from "next/server"

import { exchangeCode, validateIdToken } from "@/lib/server/oidc"
import { getOidcConfig } from "@/lib/server/oidc-config"
import { DEFAULT_LANDING } from "@/lib/server/redirect"
import {
  cookieOptions,
  openFlow,
  PORTAL_FLOW_COOKIE,
  PORTAL_SESSION_COOKIE,
  sealSession,
} from "@/lib/server/secure-cookie"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// This URL is the bootstrap-registered redirect URI: `{PortalURL}/auth/callback`.
const LOGIN = "/auth/login"

// Self-redirects are anchored to the canonical portal origin (AO_PORTAL_URL),
// not req.nextUrl.origin — behind a TLS-terminating reverse proxy the latter is
// the internal host (e.g. localhost:3001), which would leak into the redirect.
function portalURL(path: string): URL {
  return new URL(path, getOidcConfig().portalUrl)
}

// On any failure, bounce to login AND clear the (single-use) flow cookie so a
// stale flow can't feed a retry loop.
function fail(error: string) {
  const url = portalURL(LOGIN)
  url.searchParams.set("error", error)
  const res = NextResponse.redirect(url)
  res.cookies.set(PORTAL_FLOW_COOKIE, "", { ...cookieOptions, maxAge: 0 })
  return res
}

// GET /auth/callback — finish the authorization-code flow.
//
// Reads the sealed pending-flow cookie (CSRF/replay defense: its `state` must
// match the query `state`), exchanges the code with the stored PKCE verifier,
// validates the id_token (iss/aud/nonce/exp), then seals the token set into the
// session cookie. Unlike console-ui there is NO membership gate: any
// authenticated user may use the portal.
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
  const flow = await openFlow(req.cookies.get(PORTAL_FLOW_COOKIE)?.value)
  if (!flow || flow.state !== state) {
    return fail("invalid_state")
  }

  let tokens
  try {
    tokens = await exchangeCode(code, flow.verifier)
  } catch (err) {
    console.error("portal: token exchange failed", err)
    return fail("exchange_failed")
  }
  if (!tokens.idToken) {
    return fail("missing_id_token")
  }

  let sub: string
  try {
    sub = await validateIdToken(tokens.idToken, flow.nonce)
  } catch (err) {
    console.error("portal: id_token validation failed", err)
    return fail("idtoken_invalid")
  }

  // Finalize: land the user, hand the browser the sealed session, and drop the
  // now-consumed flow cookie.
  const res = NextResponse.redirect(portalURL(flow.returnTo || DEFAULT_LANDING))
  res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession({ sub, ...tokens }), cookieOptions)
  res.cookies.set(PORTAL_FLOW_COOKIE, "", { ...cookieOptions, maxAge: 0 })
  return res
}
