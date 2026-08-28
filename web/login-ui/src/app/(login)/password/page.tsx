"use client"

import { StepPassword } from "@/components/login/steps/step-password"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { messageForError, stepFor } from "@/lib/login-client"
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
        // The gateway signals the next step via methods. stepFor holds the
        // mapping, because the finalize step routes on the same answer when it
        // refuses a session that skipped one of these routes.
        setMethods(result.methods)
        navigate(stepFor(result.methods), "forward")
        return null
      }}
    />
  )
}
