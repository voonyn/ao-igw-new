import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

type Ctx = { params: Promise<{ id: string }> }

// DELETE /api/account/passkeys/:id — BFF proxy for passkey removal.
//
// Forwards the delete to the gateway with the server-held bearer. The gateway
// scopes removal to the caller's own `sub`, so an id that is not the caller's
// returns 404 (no cross-user reach) — this route just relays it.
export async function DELETE(req: NextRequest, ctx: Ctx) {
  const { id } = await ctx.params
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL(`/api/v1/account/passkeys/${encodeURIComponent(id)}`, getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    if (res.status === 200) {
      return await withRotation(NextResponse.json({ ok: true }), rotated, next)
    }
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account passkey delete proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
