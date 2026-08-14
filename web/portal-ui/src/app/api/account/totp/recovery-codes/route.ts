import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/totp/recovery-codes — BFF proxy for replacing the caller's
// recovery codes.
//
// Forwards the user's access token server-side (the browser never sees it) to the
// gateway account API, which atomically invalidates every previous code and returns
// a fresh set ({recoveryCodes}) disclosed in this response only — passed through
// verbatim so the view can show them once. There is no request body: the endpoint
// acts solely on the token `sub`.
export async function POST(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL("/api/v1/account/totp/recovery-codes", getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account totp recovery-codes proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
