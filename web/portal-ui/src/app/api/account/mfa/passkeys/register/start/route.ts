import { NextRequest } from "next/server"

import { forwardToAccountAPI } from "@/lib/server/account-proxy"
import { getOidcConfig } from "@/lib/server/oidc-config"

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
// This route names the portal's own origin in the `Origin` header. The call is
// server to server, so no browser sends one, and the browser that runs the
// ceremony runs it at this origin: `AO_PORTAL_URL` is the same value the
// deployment puts in `AO_WEBAUTHN_ORIGINS`. The gateway keeps only the origins
// the tenant relying party covers, and it refuses the start when this one is
// not among them. A deployment that names no portal origin is then refused
// before the device prompt opens, with `passkey_origin_refused`, instead of
// after the person touched the reader for a key pair no sign-in can answer.
//
// The finish sends no origin. The start already refused every ceremony this
// check would refuse, and the library compares the origin the device signed
// against the same list.
//
// The gateway spends the shared second-factor guessing budget here, so a start
// can answer `rate_limited`.
export async function POST(req: NextRequest) {
  return forwardToAccountAPI(req, "/mfa/passkeys/register/start", {
    method: "POST",
    origin: new URL(getOidcConfig().portalUrl).origin,
  })
}
