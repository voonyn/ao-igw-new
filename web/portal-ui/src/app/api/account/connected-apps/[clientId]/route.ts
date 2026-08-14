import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "@/lib/server/oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"
import { resolveAccessToken } from "@/lib/server/token"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

type Ctx = { params: Promise<{ clientId: string }> }

// DELETE /api/account/connected-apps/:clientId — BFF proxy for withdrawing one
// app's access (the remembered consent AND that client's live grants).
//
// The client id is a lookup key inside an already caller-scoped predicate at the
// gateway, so a hand-crafted id revokes nothing that is not the caller's: it
// comes back 404, exactly like a first-party or unknown client. The segment is
// URL-encoded on the way out and never parsed here.
export async function DELETE(req: NextRequest, ctx: Ctx) {
  const { clientId } = await ctx.params
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL(`/api/v1/account/connected-apps/${encodeURIComponent(clientId)}`, getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      cache: "no-store",
    })
    if (res.status === 200) {
      return await withRotation(NextResponse.json({ ok: true }), rotated, next)
    }
    // Relay the gateway's coarse code + status (not_found / unauthorized /
    // rate_limited) so the view can reconcile a 404 rather than show a failure.
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error("portal: account connected-app revoke proxy failed", err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
