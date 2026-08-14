import { NextRequest, NextResponse } from "next/server"

import { discover, getOidcConfig } from "@/lib/server/oidc-config"
import { challengeS256, createVerifier, randomToken } from "@/lib/server/pkce"
import { sanitizeReturnTo } from "@/lib/server/redirect"
import { cookieOptions, CONSOLE_FLOW_COOKIE, sealFlow } from "@/lib/server/secure-cookie"

// Node crypto (PKCE) runs on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// GET /auth/login — start the authorization-code + PKCE flow.
//
// Generates a fresh verifier/state/nonce, seals them into a short-lived httpOnly
// flow cookie (correlated to the callback by `state`), and redirects the browser
// to the gateway authorize endpoint as the
// bootstrap-seeded `console-ui` public client. The gateway delegates the actual
// login to login-ui via its LoginPolicy.
export async function GET(req: NextRequest) {
  const cfg = getOidcConfig()
  if (!cfg.clientId) {
    return NextResponse.json({ error: "console_not_configured" }, { status: 500 })
  }

  const returnTo = sanitizeReturnTo(req.nextUrl.searchParams.get("returnTo"))
  const verifier = createVerifier()
  const challenge = await challengeS256(verifier)
  const state = randomToken(24)
  const nonce = randomToken(24)

  const { authorization_endpoint } = await discover(cfg.issuer)
  const authorize = new URL(authorization_endpoint)
  authorize.searchParams.set("response_type", "code")
  authorize.searchParams.set("client_id", cfg.clientId)
  authorize.searchParams.set("redirect_uri", cfg.redirectUri)
  authorize.searchParams.set("scope", cfg.scope)
  // RFC 8707 resource indicator → the issued access token's `aud` designates the
  // admin API, which the gateway's resource server requires. Sent once here; the
  // grant carries it onto the token (and refreshes), so the exchange need not repeat it.
  authorize.searchParams.set("resource", cfg.adminResource)
  authorize.searchParams.set("state", state)
  authorize.searchParams.set("nonce", nonce)
  authorize.searchParams.set("code_challenge", challenge)
  authorize.searchParams.set("code_challenge_method", "S256")

  const res = NextResponse.redirect(authorize.toString())
  // The pending flow travels with the browser (sealed), so /auth/callback finds
  // it without any server-side store — surviving next-dev route re-eval and scale.
  res.cookies.set(CONSOLE_FLOW_COOKIE, await sealFlow({ state, verifier, nonce, returnTo }), cookieOptions)
  return res
}
