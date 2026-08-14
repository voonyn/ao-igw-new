import { cookies, headers } from "next/headers"
import { redirect } from "next/navigation"

import { SESSION_COOKIE, parseSessionCookie } from "@/lib/session-cookie"
import { resolveSession, silentComplete } from "@/lib/login-api"
import { sanitizeRedirectUri } from "@/lib/redirect"
import { IdentifierClient } from "./identifier-client"

// Server component: it owns both SSO fast-paths off the session cookie.
//   - Entered with an `authRequest` (from an OIDC client): finalize silently and
//     redirect to the provider resume URL. When the auth request demands
//     interaction (prompt=login / unsatisfied max_age) or the cookie is dead,
//     silentComplete returns null and the interactive flow renders.
//   - Entered standalone (manual browse, no `authRequest`): when the cookie
//     resolves to a live, fully authenticated session, the user is already
//     signed in, so redirect straight to the validated `redirect_uri` when one
//     was supplied, otherwise to the signed-in screen.
// A dead/partial cookie falls through and is simply overwritten by the next
// /check. `redirect_uri` is validated server-side here (open-redirect guard)
// before it is ever acted on or carried into the client flow.
export default async function LoginIdentifierPage({
  searchParams,
}: {
  searchParams: Promise<{ authRequest?: string; redirect_uri?: string }>
}) {
  const { authRequest, redirect_uri } = await searchParams
  const host = (await headers()).get("host") ?? ""
  const redirectUri = sanitizeRedirectUri(redirect_uri, host)

  const cookieStore = await cookies()
  const parsed = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (parsed) {
    if (authRequest) {
      const redirectTo = await silentComplete(parsed.token, authRequest, host)
      if (redirectTo) {
        redirect(redirectTo)
      }
    } else if (await resolveSession(parsed.token, host)) {
      redirect(redirectUri || "/success")
    }
  }

  return <IdentifierClient authRequest={authRequest ?? ""} redirectUri={redirectUri} />
}
