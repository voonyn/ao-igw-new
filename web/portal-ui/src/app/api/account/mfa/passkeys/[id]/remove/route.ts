import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/mfa/passkeys/[id]/remove — BFF proxy for the removal.
//
// The current password travels in the body, because it is the whole proof of
// the request: the access token carries no session identifier, and the gateway
// guard reads no store. The password is forwarded and never logged.
//
// The address is POST and not DELETE, because it carries a body. A body on a
// DELETE is what proxies and clients drop. The TOTP removal reads the same way.
export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params
  const body = await req.json().catch(() => ({}))
  return forwardToAccountAPI(req, `/mfa/passkeys/${encodeURIComponent(id)}/remove`, {
    method: "POST",
    body: { password: body?.password },
  })
}
