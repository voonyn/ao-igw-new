import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/mfa/passkeys/register/start — BFF proxy for the ceremony start.
//
// The answer is carried across as one opaque object, and no field of it is read
// here. Every field is part of what the device will sign, so a value this route
// picked out and rebuilt would change what the signature covers. The browser
// hands the object to the platform, which parses it.
//
// This route sends no browser `Origin`: the call is server to server. The
// gateway does not need one. It keeps only the origins the tenant relying party
// covers, and refuses the ceremony when that list is empty.
//
// The gateway spends the shared second-factor guessing budget here, so a start
// can answer `rate_limited`.
export async function POST(req: NextRequest) {
  return forwardToAccountAPI(req, "/mfa/passkeys/register/start", { method: "POST" })
}
