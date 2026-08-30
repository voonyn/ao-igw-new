import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"

// Route reads the server-held token and calls the gateway on Node.
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// POST /api/account/mfa/passkeys/register/finish — BFF proxy for the ceremony end.
//
// The body is forwarded whole, and no field of it is read here. The device
// signed over the answer, so a route that picked fields out and rebuilt the
// object would hand the gateway something the signature no longer covers. The
// gateway is the first thing that reads inside it.
//
// The body is `{ credential, name }`: the object the browser produced, and what
// the person calls the device. A success answers 201.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}))
  return forwardToAccountAPI(req, "/mfa/passkeys/register/finish", { method: "POST", body })
}
