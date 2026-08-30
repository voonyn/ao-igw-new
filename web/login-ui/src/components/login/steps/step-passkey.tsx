"use client"

import * as React from "react"

import {
  BackLink,
  Heading,
  LinkButton,
  PrimaryButton,
  StepIcon,
  Subtext,
} from "../parts"
import { AlertCircleIcon, PasskeyIcon } from "../icons"

// StepPasskey is the Passkey challenge of the sign-in.
//
// It is a Client Component because the browser call needs a real user gesture.
// The person presses the button, the device asks for a fingerprint or a PIN, and
// the answer goes back to the gateway.
//
// The control is always rendered. A browser that cannot run the ceremony gets it
// disabled with a short reason beside it, because a person who sees no control
// cannot tell a missing feature from a broken page.
//
// onAnother is the other Second Factor. It is offered only when the sign-in owes
// a second step, so a person whose device is at home reaches the Authenticator
// without help, and a person who holds one Factor reads no dead link.
export function StepPasskey({
  supported,
  onVerify,
  onAnother,
  onBack,
}: {
  /** Whether this browser can run the ceremony at all. */
  supported: boolean
  /** Runs the whole ceremony. Resolves to an error message to display, "" when
   *  the person cancelled, or null on success (the parent navigates forward,
   *  unmounting this step). */
  onVerify: () => Promise<string | null>
  /** Routes to the other Second Factor, or undefined when the sign-in owes none. */
  onAnother?: () => void
  onBack: () => void
}) {
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (loading || !supported) return

    setError(null)
    setLoading(true)
    const err = await onVerify()
    if (err !== null) {
      // A cancel answers the empty string. It is a choice and not a failure, so
      // the screen shows nothing and is usable again at once.
      setError(err || null)
      setLoading(false)
    }
  }

  return (
    <>
      <StepIcon>
        <PasskeyIcon />
      </StepIcon>
      <Heading>Use your passkey</Heading>
      <Subtext>
        {supported
          ? "Confirm it’s you with your fingerprint, face, screen lock, or security key."
          : "This browser cannot use passkeys."}
      </Subtext>

      <form onSubmit={handleSubmit} noValidate>
        <PrimaryButton
          loading={loading}
          loadingLabel="Waiting for your device"
          disabled={!supported || loading}
          autoFocus
        >
          Continue with passkey
        </PrimaryButton>
      </form>

      {error && (
        <p
          role="alert"
          className="mt-3.5 flex items-center justify-center gap-[5px] text-[12.5px] font-medium text-ao-error"
        >
          <AlertCircleIcon className="size-[13px]" />
          <span>{error}</span>
        </p>
      )}

      {onAnother && (
        <p className="mt-[18px] text-center">
          <LinkButton onClick={onAnother}>Use another method</LinkButton>
        </p>
      )}

      <p className="mt-3 text-center text-[12.5px] text-pretty text-ao-muted">
        {supported
          ? "Your passkey never leaves your device. Nothing is typed, and nothing is stored here that another site could use."
          : "Use another method on this browser, or sign in on a device that supports passkeys."}
      </p>

      <BackLink onClick={onBack} />
    </>
  )
}
