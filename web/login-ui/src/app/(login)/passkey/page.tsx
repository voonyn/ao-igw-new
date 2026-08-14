"use client"

import { StepPasskey } from "@/components/login/steps/step-passkey"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { beginPasskeyLogin, finishPasskeyLogin } from "./actions"

export default function LoginPasskeyPage() {
  const email = useRequireEmail()
  const { navigate, methods } = useLoginFlow()

  if (!email) return null

  // When TOTP is also enrolled, offer it as the alternative (the method picker).
  const alsoOtp = methods.includes("otp")

  return (
    <StepPasskey
      mode="challenge"
      onBegin={beginPasskeyLogin}
      onFinish={finishPasskeyLogin}
      onDone={() => navigate("/success", "forward")}
      onBack={() => navigate("/password", "back")}
      altLabel={alsoOtp ? "Use your authenticator app instead" : undefined}
      onAlt={alsoOtp ? () => navigate("/verify", "forward") : undefined}
    />
  )
}
