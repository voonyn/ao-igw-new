import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/mfa/totp/enroll/start — BFF proxy for the enrolment start.
//
// Answers `{ secret, otpauthUri }`. The gateway records no factor here, so a
// person who abandons the setup keeps the account they had.
//
// The gateway refuses a start against an active factor with `mfa_already_enrolled`.
export async function POST(req: NextRequest) {
  return forwardToAccountAPI(req, "/mfa/totp/enroll/start", { method: "POST" })
}
