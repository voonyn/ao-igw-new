import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

/**
 * Proxies OIDC protocol paths to the Go backend (AO_API_URL).
 *
 * Required for the separate-FQDN deployment where the login UI lives on
 * dev-auth.alpha-omega.io and the Go backend (OIDC issuer) lives on
 * dev-api.alpha-omega.io. Without this proxy, OIDC clients would receive a
 * discovery document whose issuer doesn't match the domain they're talking to,
 * breaking every OIDC client library.
 *
 * Paths proxied (browser sees auth domain; Go sees the real request):
 *   /.well-known/*  — OpenID Connect discovery document
 *   /oauth/*        — OAuth 2 protocol (authorize, token, revoke, introspect)
 *   /oidc/*         — OIDC protocol (userinfo, JWKS, end_session)
 *
 * AO_API_URL is a server-only env var — never exposed to the client bundle.
 */
export function proxy(request: NextRequest) {
  const goBackendURL = process.env.AO_API_URL ?? "http://localhost:8080"
  const { pathname, search } = request.nextUrl

  const target = new URL(pathname + search, goBackendURL)
  return NextResponse.rewrite(target)
}

export const config = {
  matcher: ["/.well-known/:path*", "/oauth/:path*", "/oidc/:path*"],
}
