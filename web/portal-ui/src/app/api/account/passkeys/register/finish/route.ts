import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/passkeys/register/finish — BFF proxy for passkey enrolment step 2.
//
// Relays the authenticator attestation (the raw body from
// `navigator.credentials.create()`) plus an optional `name` label to the gateway
// with the user's bearer, forwarding the browser Origin as in `begin` so the
// gateway can bind/validate the ceremony origin. The gateway verifies the
// attestation and stores the credential's public key; a bad/stale ceremony fails
// with a single generic error this route passes straight through.
export async function POST(req: NextRequest) {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const name = req.nextUrl.searchParams.get("name") ?? ""
  const rawBody = await req.text()
  const browserOrigin = req.headers.get("origin") ?? new URL(req.url).origin
  const path = `/api/v1/account/passkeys/register/finish${name ? `?name=${encodeURIComponent(name)}` : ""}`
  const url = new URL(path, getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        Origin: browserOrigin,
      },
      body: rawBody,
      cache: "no-store",
    })
    if (res.status === 200) {
      return await withRotation(NextResponse.json({ ok: true }), rotated, next)
    }
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account passkey finish proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
