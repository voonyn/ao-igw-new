import { cookies, headers } from "next/headers"

import { SESSION_COOKIE, parseSessionCookie } from "@/lib/session-cookie"
import { resolveSession } from "@/lib/login-api"
import { sanitizeRedirectUri } from "@/lib/redirect"
import { SuccessClient } from "./success-client"

// Server component: it resolves whether a live, fully authenticated session
// backs this visit. That lets the signed-in screen render on a standalone visit
// (manual browse with an SSO cookie) where the client flow context is empty —
// the in-progress email is no longer the only proof of "signed in". When an
// authRequest is carried through the flow, the client still finalizes against
// the provider. A `redirect_uri` carried in the flow (or present directly on
// this URL, validated here) sends the browser onward instead of dead-ending on
// the signed-in screen.
export default async function LoginSuccessPage({
  searchParams,
}: {
  searchParams: Promise<{ redirect_uri?: string }>
}) {
  const { redirect_uri } = await searchParams
  const host = (await headers()).get("host") ?? ""
  const parsed = parseSessionCookie((await cookies()).get(SESSION_COOKIE)?.value)
  let signedIn = false
  if (parsed) {
    signedIn = (await resolveSession(parsed.token, host)) !== null
  }
  return (
    <SuccessClient
      serverSignedIn={signedIn}
      serverRedirectUri={sanitizeRedirectUri(redirect_uri, host)}
    />
  )
}
