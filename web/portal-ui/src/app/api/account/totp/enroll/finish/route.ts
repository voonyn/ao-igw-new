import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/totp/enroll/finish — BFF proxy for authenticator enrolment step 2.
//
// Relays the `{code}` body (the 6-digit code from the authenticator) to the gateway
// with the user's bearer. On success the gateway activates the factor and returns the
// one-time recovery codes ({recoveryCodes}) — passed straight through so the view can
// show them once. A wrong code fails generically and this route relays it.
export async function POST(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const rawBody = await req.text()
  const url = new URL("/api/v1/account/totp/enroll/finish", getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json" },
      body: rawBody,
      cache: "no-store",
    })
    // Relay the gateway body verbatim ({recoveryCodes} on 200; a coarse code otherwise).
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account totp finish proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
