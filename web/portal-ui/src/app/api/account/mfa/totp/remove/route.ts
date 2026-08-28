import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/mfa/totp/remove — BFF proxy for the removal of the factor.
//
// The current password travels in the body, because it is the whole proof of the
// request: the access token carries no session identifier, and the gateway guard
// reads no store. The password is forwarded and never logged.
//
// The gateway hard deletes the shared secret and every Recovery Code, so a later
// enrolment starts clean. No other login session ends.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}))
  return forwardToAccountAPI(req, "/mfa/totp/remove", {
    method: "POST",
    body: { password: body?.password },
  })
}
