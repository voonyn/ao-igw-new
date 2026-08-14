"use client"

import { StepMfaEnroll } from "@/components/login/steps/step-mfa-enroll"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { startEnrollment, activateEnrollment } from "./actions"

export default function LoginEnrollPage() {
  const email = useRequireEmail()
  const { navigate } = useLoginFlow()

  if (!email) return null

  return (
    <StepMfaEnroll
      onStart={startEnrollment}
      onActivate={activateEnrollment}
      onDone={() => navigate("/success", "forward")}
      onBack={() => navigate("/password", "back")}
    />
  )
}
