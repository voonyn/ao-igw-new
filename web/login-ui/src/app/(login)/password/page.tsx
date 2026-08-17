"use client"

import { StepPassword } from "@/components/login/steps/step-password"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { messageForError } from "@/lib/login-client"
import { submitPassword } from "./actions"

export default function LoginPasswordPage() {
  const email = useRequireEmail()
  const { navigate, setMethods } = useLoginFlow()

  if (!email) return null

  return (
    <StepPassword
      email={email}
      onBack={() => navigate("/identifier", "back")}
      onSubmit={async (password) => {
        const result = await submitPassword(password)
        if (!result.ok) return messageForError(result.error)
        // The gateway signals the next step via methods. A passkey and TOTP are
        // interchangeable second factors; `webauthn`/`otp` challenge an enrolled
        // user and `webauthn_enroll`/`otp_enroll` force setup when policy requires
        // MFA. WebAuthn is preferred (phishing-resistant); the challenge step offers
        // the other method as a picker. An empty set proceeds straight to finalize.
        setMethods(result.methods)
        const m = result.methods
        const next = m.includes("webauthn")
          ? "/passkey"
          : m.includes("otp")
            ? "/verify"
            : m.includes("webauthn_enroll")
              ? "/passkey-enroll"
              : m.includes("otp_enroll")
                ? "/enroll"
                : "/success"
        navigate(next, "forward")
        return null
      }}
    />
  )
}
