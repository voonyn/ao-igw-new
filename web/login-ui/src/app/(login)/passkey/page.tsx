"use client"

import * as React from "react"

import { StepPasskey } from "@/components/login/steps/step-passkey"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { browserPasskeyMessage, getPasskey, passkeyMessage, passkeysSupported } from "@/lib/webauthn"
import { finishPasskeyChallenge, startPasskeyChallenge } from "./actions"

// The Passkey challenge step.
//
// The whole ceremony runs from one press: the Server Action asks the gateway for
// the options, the browser hands them to the device, and the answer goes back
// through a second Server Action. The options and the answer cross this file
// whole, because every field of them is covered by what the device signs.
export default function LoginPasskeyPage() {
  const email = useRequireEmail()
  const { methods, navigate } = useLoginFlow()

  // The pending browser prompt. Leaving this screen aborts it, so a person who
  // switches to the Authenticator is not left with a browser sheet over a screen
  // that moved on.
  const ceremony = React.useRef<AbortController | null>(null)
  React.useEffect(() => () => ceremony.current?.abort(), [])

  // The feature check reads `window`, and the server renders no window. React
  // subscribes to it instead of an effect: the server answer enables the control,
  // and the browser answer replaces it right after hydration. Nothing changes it
  // after that, so the subscribe below has nothing to report.
  const supported = React.useSyncExternalStore(
    () => () => {},
    passkeysSupported,
    () => true,
  )

  // The other Second Factor, offered only when the sign-in owes it too.
  const another = methods.includes("otp") ? () => navigate("/verify", "forward") : undefined

  if (!email) return null

  return (
    <StepPasskey
      supported={supported}
      onAnother={another}
      onBack={() => navigate("/password", "back")}
      onVerify={async () => {
        const started = await startPasskeyChallenge()
        if (!started.ok) return passkeyMessage(started.error)

        const controller = new AbortController()
        ceremony.current = controller

        let credential
        try {
          credential = await getPasskey(started.options, controller.signal)
        } catch (err) {
          return browserPasskeyMessage(err)
        } finally {
          ceremony.current = null
        }

        const finished = await finishPasskeyChallenge(credential)
        if (!finished.ok) return passkeyMessage(finished.error)

        navigate("/success", "forward")
        return null
      }}
    />
  )
}
