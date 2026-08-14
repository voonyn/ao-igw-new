import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// GET /api/account/passkeys — BFF proxy for the self-service passkey listing.
//
// Forwards the user's access token server-side (keyed by the sealed cookie; the
// browser never sees it) to the gateway account API. The gateway scopes the list
// to the token `sub`, so only the caller's own passkeys (metadata only) come back.
export async function GET(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL("/api/v1/account/passkeys", getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    if (res.status === 200) {
      const passkeys = await res.json().catch(() => [])
      return await withRotation(NextResponse.json({ passkeys }), rotated, next)
    }
    // Pass the gateway's coarse code + status through (unauthorized / rate_limited).
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account passkeys list proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
