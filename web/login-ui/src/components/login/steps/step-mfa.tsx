"use client"

import * as React from "react"
import { REGEXP_ONLY_DIGITS } from "input-otp"

import { cn } from "@/lib/utils"
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp"
import {
  BackLink,
  Heading,
  LinkButton,
  PrimaryButton,
  StepIcon,
  Subtext,
  TextField,
} from "../parts"
import { AlertCircleIcon, LockIcon, MfaIcon } from "../icons"

export function StepMfa({
  onBack,
  onVerify,
  onPasskey,
}: {
  onBack: () => void
  /** Verifies a TOTP or recovery code. Resolves to an error message to display,
   *  or null on success (the parent navigates forward, unmounting this step). */
  onVerify: (code: string) => Promise<string | null>
  /** Routes back to the passkey challenge, or undefined when the sign-in owes
   *  none. A person who holds both Second Factors reaches either one from here. */
  onPasskey?: () => void
}) {
  const [mode, setMode] = React.useState<"totp" | "recovery">("totp")
  const [code, setCode] = React.useState("")
  const [recovery, setRecovery] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)

  const value = mode === "totp" ? code : recovery.trim()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (loading) return
    if (mode === "totp" && code.length < 6) {
      setError("Please enter all 6 digits.")
      return
    }
    if (mode === "recovery" && !recovery.trim()) {
      setError("Please enter a recovery code.")
      return
    }
    setError(null)
    setLoading(true)
    const err = await onVerify(value)
    if (err) {
      setError(err)
      setLoading(false)
      if (mode === "totp") setCode("")
    }
  }

  function switchMode() {
    setMode((m) => (m === "totp" ? "recovery" : "totp"))
    setCode("")
    setRecovery("")
    setError(null)
  }

  const invalid = Boolean(error)
  const slotClass = cn(
    "h-[58px] w-full rounded-[10px] border-[1.5px]! border-input bg-ao-field text-[22px] font-semibold text-ao-ink transition-[border-color,box-shadow,background-color] max-[520px]:h-[52px] max-[520px]:text-[20px]",
    "data-[active=true]:z-10 data-[active=true]:border-primary data-[active=true]:bg-white data-[active=true]:ring-4 data-[active=true]:ring-[var(--ao-orange-soft)]",
    "data-[filled=true]:border-primary data-[filled=true]:bg-white",
    invalid &&
      "border-destructive bg-ao-error-bg data-[active=true]:border-destructive data-[active=true]:ring-destructive/15 data-[filled=true]:border-destructive"
  )

  return (
    <>
      <StepIcon>
        <MfaIcon />
      </StepIcon>
      <Heading>Two-factor authentication</Heading>
      <Subtext>
        {mode === "totp"
          ? "Enter the 6-digit code from your authenticator app to verify it’s you."
          : "Enter one of your saved recovery codes. Each code works only once."}
      </Subtext>

      <form onSubmit={handleSubmit} noValidate>
        {mode === "totp" ? (
          <>
            <InputOTP
              maxLength={6}
              pattern={REGEXP_ONLY_DIGITS}
              value={code}
              onChange={(v) => {
                setCode(v)
                if (error) setError(null)
              }}
              aria-invalid={invalid}
              autoFocus
              containerClassName="w-full"
            >
              <InputOTPGroup className="grid w-full grid-cols-6 gap-2.5 max-[520px]:gap-[7px]">
                {[0, 1, 2, 3, 4, 5].map((i) => (
                  <InputOTPSlot key={i} index={i} className={slotClass} />
                ))}
              </InputOTPGroup>
            </InputOTP>

            {invalid && (
              <p className="mt-3.5 flex items-center justify-center gap-[5px] text-[12.5px] font-medium text-ao-error">
                <AlertCircleIcon className="size-[13px]" />
                <span>{error}</span>
              </p>
            )}
          </>
        ) : (
          <TextField
            id="recoveryCode"
            name="recoveryCode"
            type="text"
            label="Recovery code"
            placeholder="Enter a recovery code"
            autoComplete="one-time-code"
            autoFocus
            icon={<LockIcon />}
            error={error}
            value={recovery}
            onChange={(e) => {
              setRecovery(e.target.value)
              if (error) setError(null)
            }}
          />
        )}

        <PrimaryButton loading={loading} loadingLabel="Verifying">
          Verify
        </PrimaryButton>
      </form>

      <p className="mt-[18px] text-center">
        <LinkButton onClick={switchMode}>
          {mode === "totp" ? "Use a recovery code instead" : "Use your authenticator app"}
        </LinkButton>
      </p>

      {onPasskey && (
        <p className="mt-2 text-center">
          <LinkButton onClick={onPasskey}>Use your passkey instead</LinkButton>
        </p>
      )}

      <p className="mt-3 text-center text-[12.5px] text-pretty text-ao-muted">
        Lost your authenticator app and used every recovery code? An administrator can
        reset two-factor authentication for you. The reset deletes your current secret
        and all remaining recovery codes, and you set it up again at your next sign-in.
      </p>

      <BackLink onClick={onBack} />
    </>
  )
}
