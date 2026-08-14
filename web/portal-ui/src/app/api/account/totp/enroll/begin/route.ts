import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/totp/enroll/begin — BFF proxy for authenticator enrolment step 1.
//
// Forwards the user's bearer to the gateway and returns the pending secret + the
// otpauth:// provisioning URI ({secret, otpauthUri}) for the portal to render a QR.
// The caller's email (already in the portal session) is forwarded as ?account= — a
// purely cosmetic label for the authenticator-app entry; the gateway uses it only as
// the URI label and falls back to the token `sub`, so it never influences identity.
export async function POST(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const account = req.nextUrl.searchParams.get("account") ?? ""
  const path = `/api/v1/account/totp/enroll/begin${account ? `?account=${encodeURIComponent(account)}` : ""}`
  const url = new URL(path, getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account totp begin proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
