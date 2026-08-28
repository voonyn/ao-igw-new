import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// GET /api/account/mfa — BFF proxy for the second-factor state of the caller.
//
// Answers `{ active, activatedAt?, recoveryCodesRemaining }`. The gateway sends
// no secret and no code here, so nothing on this answer is a credential.
export async function GET(req: NextRequest) {
  return forwardToAccountAPI(req, "/mfa")
}
