import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// PATCH /api/account/mfa/passkeys/[id] — BFF proxy for the rename.
//
// The id is the base64url credential id the list answered. It is a public
// handle and never a credential: every assertion sends it in the clear. It is
// encoded into the path, so a value the browser did not produce cannot reach
// another address of the gateway.
//
// The body is `{ name }`. A success answers 200 with an empty payload, and the
// card re-reads the list.
export async function PATCH(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params
  const body = await req.json().catch(() => ({}))
  return forwardToAccountAPI(req, `/mfa/passkeys/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: { name: body?.name },
  })
}
