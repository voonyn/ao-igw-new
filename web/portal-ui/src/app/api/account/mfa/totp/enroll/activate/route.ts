import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/mfa/totp/enroll/activate — BFF proxy for the activation.
//
// Forwards the 6-digit code the Authenticator shows, and answers the Recovery
// Codes. The gateway discloses them exactly once, so the view shows them and
// no later read can name them again.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}))
  return forwardToAccountAPI(req, "/mfa/totp/enroll/activate", {
    method: "POST",
    body: { code: body?.code },
  })
}
