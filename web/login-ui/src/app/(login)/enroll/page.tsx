"use client"

import * as React from "react"

import { StepMfaEnroll } from "@/components/login/steps/step-mfa-enroll"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { browserPasskeyMessage, createPasskey, passkeyMessage, passkeysSupported } from "@/lib/webauthn"
import {
  activateEnrollment,
  finishPasskeyEnrollment,
  startEnrollment,
  startPasskeyEnrollment,
} from "./actions"

// The forced enrolment step. The MFA Requirement governs the person, they hold
// no Second Factor, and they enrol one here.
//
// Both Factors are offered on one screen, the Passkey first, and neither is
// conditional. A device with no authenticator must never dead-end, so the
// authenticator app is there whatever the browser can do.
//
// A person who enrols a Passkey continues straight to the application. The
// gateway records the factor on the same transaction the Passkey lands on, so
// there is no second challenge to answer.
export default function LoginEnrollPage() {
  const email = useRequireEmail()
  const { navigate } = useLoginFlow()

  // The pending browser prompt. Both ways out of it abort: leaving the screen,
  // and switching to the authenticator app, which keeps this screen mounted. A
  // person who switches is never left with a browser sheet over a screen that
  // moved on.
  const ceremony = React.useRef<AbortController | null>(null)
  React.useEffect(() => () => ceremony.current?.abort(), [])
  const abandon = React.useCallback(() => ceremony.current?.abort(), [])

  // The feature check reads `window`, and the server renders no window. React
  // subscribes to it instead of an effect: the server answer enables the control,
  // and the browser answer replaces it right after hydration. Nothing changes it
  // after that, so the subscribe below has nothing to report.
  const supported = React.useSyncExternalStore(
    () => () => {},
    passkeysSupported,
    () => true,
  )

  if (!email) return null

  return (
    <StepMfaEnroll
      passkeySupported={supported}
      onAbandonPasskey={abandon}
      onStart={startEnrollment}
      onActivate={activateEnrollment}
      onDone={() => navigate("/success", "forward")}
      onBack={() => navigate("/password", "back")}
      onEnrollPasskey={async () => {
        const started = await startPasskeyEnrollment()
        if (!started.ok) return passkeyMessage(started.error)

        const controller = new AbortController()
        ceremony.current = controller

        let credential
        try {
          credential = await createPasskey(started.options, controller.signal)
        } catch (err) {
          return browserPasskeyMessage(err)
        } finally {
          ceremony.current = null
        }

        const finished = await finishPasskeyEnrollment(credential)
        if (!finished.ok) return passkeyMessage(finished.error)

        navigate("/success", "forward")
        return null
      }}
    />
  )
}
