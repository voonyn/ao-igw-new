"use client"

import { StepPasskey } from "@/components/login/steps/step-passkey"
import { useLoginFlow, useRequireEmail } from "@/components/login/flow-context"
import { beginPasskeyRegister, finishPasskeyRegister } from "../passkey/actions"

export default function LoginPasskeyEnrollPage() {
  const email = useRequireEmail()
  const { navigate, methods } = useLoginFlow()

  if (!email) return null

  // When TOTP enrollment is also offered, let the user set that up instead (picker).
  const alsoOtpEnroll = methods.includes("otp_enroll")

  return (
    <StepPasskey
      mode="register"
      onBegin={beginPasskeyRegister}
      onFinish={finishPasskeyRegister}
      onDone={() => navigate("/success", "forward")}
      onBack={() => navigate("/password", "back")}
      altLabel={alsoOtpEnroll ? "Set up an authenticator app instead" : undefined}
      onAlt={alsoOtpEnroll ? () => navigate("/enroll", "forward") : undefined}
    />
  )
}
