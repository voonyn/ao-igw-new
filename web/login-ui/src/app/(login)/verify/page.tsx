"use client"

import { StepMfa } from "@/components/login/steps/step-mfa"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { mfaMessageForError } from "@/lib/login-client"
import { submitMfaVerify } from "./actions"

export default function LoginVerifyPage() {
  const email = useRequireEmail()
  const { methods, navigate } = useLoginFlow()

  if (!email) return null

  return (
    <StepMfa
      onBack={() => navigate("/password", "back")}
      onPasskey={
        methods.includes("webauthn") ? () => navigate("/passkey", "back") : undefined
      }
      onVerify={async (code) => {
        const result = await submitMfaVerify(code)
        if (!result.ok) return mfaMessageForError(result.error)
        navigate("/success", "forward")
        return null
      }}
    />
  )
}
