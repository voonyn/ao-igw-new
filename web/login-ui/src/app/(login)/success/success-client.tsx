"use client"

import * as React from "react"
import { useRouter } from "next/navigation"

import { StepSuccess } from "@/components/login/steps/step-success"
import { StepConsent } from "@/components/login/steps/step-consent"
import { useLoginFlow } from "@/components/login/flow-context"
import { stepFor } from "@/lib/login-client"
import { completeLogin, submitConsent, type ScopeConsent } from "./actions"

export function SuccessClient({
  serverSignedIn,
  serverRedirectUri,
}: {
  serverSignedIn: boolean
  serverRedirectUri: string
}) {
  const { email, authRequest, redirectUri, methods, hydrated, navigate } = useLoginFlow()
  const router = useRouter()
  const [consent, setConsent] = React.useState<ScopeConsent[] | null>(null)
  const [consentBusy, setConsentBusy] = React.useState(false)

  // Finalize against the auth request and hand the browser to the provider
  // resume URL. When the gateway reports consent is required, render the consent
  // screen instead of redirecting. With no authRequest (standalone / demo) there
  // is nothing to finalize; the standalone redirect below takes over instead.
  React.useEffect(() => {
    if (!authRequest) return
    let cancelled = false
    void (async () => {
      const result = await completeLogin(authRequest)
      if (cancelled) return
      if (result.ok && "consentRequired" in result) {
        setConsent(result.scopes)
        return
      }
      if (result.ok) {
        window.location.assign(result.redirectTo)
        return
      }
      // A forced password change is the one expected finalize failure: the
      // gateway blocks /complete until the flag clears. Route to the change
      // step, which clears the flag and then resumes finalize (authRequest is
      // kept in sessionStorage, so the resumed /complete still has it).
      if (result.error === "password_change_required") {
        navigate("/change-password", "forward")
        return
      }
      // The gateway refused a session that still owes a second factor: the
      // person reached this screen without answering the challenge or without
      // enrolling. Route back to the step they skipped, named by the same
      // methods the password step routed on. Without this branch they wait on a
      // screen that never moves.
      if (result.error === "insufficient_factors") {
        // The password step writes the methods beside the authRequest, and a
        // refusal needs a session that proved a password, so a refusal always
        // has them. When they are somehow gone the step owed cannot be named,
        // and routing to this screen again would spin, so that case falls
        // through to the log below.
        const next = stepFor(methods)
        if (next !== "/success") {
          navigate(next, "forward")
          return
        }
      }
      // Any other failure here is genuinely unexpected, so log it rather than
      // trapping the user.
      console.error("login finalize failed", result.error)
    })()
    return () => {
      cancelled = true
    }
  }, [authRequest, methods, navigate])

  // Record the consent decision (approve or deny) and hand the browser to the
  // returned URL — the provider resume URL on approve, the client's error
  // redirect on deny.
  const decide = React.useCallback(
    (approved: boolean) => {
      setConsentBusy(true)
      void (async () => {
        const result = await submitConsent(authRequest, approved)
        if (result.ok) {
          window.location.assign(result.redirectTo)
          return
        }
        setConsentBusy(false)
        console.error("consent submit failed", result.error)
      })()
    },
    [authRequest]
  )

  // Standalone path (no OIDC request to finalize): a server-validated post-login
  // return URL was carried through the flow (or supplied on this URL). Hand the
  // browser to it instead of dead-ending on the "Redirecting…" screen. Gated on
  // an actual signed-in state so an unauthenticated deep link can't trigger it.
  const standaloneTarget = redirectUri || serverRedirectUri
  React.useEffect(() => {
    if (authRequest || !standaloneTarget) return
    if (!serverSignedIn && !email) return
    window.location.assign(standaloneTarget)
  }, [authRequest, standaloneTarget, serverSignedIn, email])

  // Bounce to the start only when neither a live server session nor an in-flow
  // email backs this screen (a dead deep link / refresh on an expired session).
  React.useEffect(() => {
    if (hydrated && !serverSignedIn && !email) router.replace("/identifier")
  }, [hydrated, serverSignedIn, email, router])

  // Consent screen takes over once /complete reports it is required (only
  // reachable with an authRequest, so it never collides with the standalone path).
  if (consent) {
    return (
      <StepConsent
        scopes={consent}
        loading={consentBusy}
        onApprove={() => decide(true)}
        onDeny={() => decide(false)}
      />
    )
  }

  if (!serverSignedIn && !email) return null

  return <StepSuccess />
}
