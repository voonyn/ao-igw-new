import { NextResponse } from "next/server"

import { discover, getOidcConfig } from "@/lib/server/oidc-config"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// Same-origin passthrough for the tenant's published JWKS. The set is public, so
// there is no token to attach — this exists only because the gateway sets no CORS
// headers, which makes the cross-origin `jwks_uri` unreadable from the browser.
// The URI comes from discovery (cached), never from a path hardcoded here.
export async function GET() {
  try {
    const { issuer } = getOidcConfig()
    const { jwks_uri } = await discover(issuer)
    const upstream = await fetch(jwks_uri, { cache: "no-store" })
    if (!upstream.ok) {
      return NextResponse.json({ error: "jwks_unavailable", status: upstream.status }, { status: 502 })
    }
    return NextResponse.json({ jwksUri: jwks_uri, jwks: await upstream.json() })
  } catch {
    return NextResponse.json({ error: "jwks_unavailable" }, { status: 502 })
  }
}
