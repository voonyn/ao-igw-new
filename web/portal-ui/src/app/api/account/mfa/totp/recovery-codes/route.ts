import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/mfa/totp/recovery-codes — BFF proxy for the replacement.
//
// The current password travels in the body, for the reason the removal states.
// The answer carries the new Recovery Codes, which the gateway discloses exactly
// once. The view shows them, and no later read can name them again.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}))
  return forwardToAccountAPI(req, "/mfa/totp/recovery-codes", {
    method: "POST",
    body: { password: body?.password },
  })
}
