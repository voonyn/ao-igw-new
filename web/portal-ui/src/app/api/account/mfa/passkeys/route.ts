import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// GET /api/account/mfa/passkeys — BFF proxy for the Passkeys of the caller.
//
// Answers a list of `{ id, name, createdAt, lastUsedAt? }`. It is one bounded
// whole and carries no pager: a person holds a handful of Passkeys.
//
// Nothing on this answer is a credential. The id is the public handle every
// assertion sends in the clear, and no public key reaches the browser.
export async function GET(req: NextRequest) {
  return forwardToAccountAPI(req, "/mfa/passkeys")
}
