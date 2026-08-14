import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/passkeys/register/begin — BFF proxy for passkey enrolment step 1.
//
// Forwards the user's bearer to the gateway and returns the WebAuthn creation
// options (`{publicKey: ...}`) for `navigator.credentials.create()`. The gateway
// binds the ceremony to the tenant RP ID and validates the ceremony origin against
// it, so this route forwards the browser's Origin (the portal page origin) — a
// header only settable on a server-side (Node) fetch. The `Origin` is advisory
// input the gateway re-checks against its server-derived RP ID; it is never trusted
// verbatim.
export async function POST(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const browserOrigin = req.headers.get("origin") ?? new URL(req.url).origin
  const url = new URL("/api/v1/account/passkeys/register/begin", getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json", Origin: browserOrigin },
      cache: "no-store",
    })
    // On success relay the creation options JSON verbatim; otherwise pass the
    // gateway's coarse code + status through.
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account passkey begin proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
