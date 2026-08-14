"use client"

import * as React from "react"

import { toCreationOptions, toRequestOptions, encodeCredential } from "@/lib/webauthn"
import { BackLink, Heading, LinkButton, PrimaryButton, StepIcon, Subtext } from "../parts"
import { AlertCircleIcon, MfaIcon } from "../icons"

type BeginResult = { ok: true; publicKey: Record<string, unknown> } | { ok: false; error: string }
type FinishResult = { ok: true } | { ok: false; error: string }

// StepPasskey drives one WebAuthn ceremony end to end: it calls `onBegin` for the
// options, runs the browser credential API (which requires the button click as its
// user gesture), then posts the encoded credential to `onFinish`. It backs both the
// register (create) and challenge (get) steps (add-webauthn-passkeys).
export function StepPasskey({
  mode,
  onBegin,
  onFinish,
  onDone,
  onBack,
  altLabel,
  onAlt,
}: {
  mode: "register" | "challenge"
  onBegin: () => Promise<BeginResult>
  onFinish: (credential: unknown) => Promise<FinishResult>
  onDone: () => void
  onBack: () => void
  /** When set, renders a secondary link to fall back to the other method (the picker). */
  altLabel?: string
  onAlt?: () => void
}) {
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)

  const supported = typeof window !== "undefined" && !!window.PublicKeyCredential

  async function run() {
    if (loading) return
    setError(null)
    setLoading(true)
    try {
      const begun = await onBegin()
      if (!begun.ok) {
        setError(messageFor(begun.error))
        setLoading(false)
        return
      }
      const credential =
        mode === "register"
          ? ((await navigator.credentials.create({
              publicKey: toCreationOptions(begun.publicKey),
            })) as PublicKeyCredential | null)
          : ((await navigator.credentials.get({
              publicKey: toRequestOptions(begun.publicKey),
            })) as PublicKeyCredential | null)

      if (!credential) {
        setError("No passkey was provided. Please try again.")
        setLoading(false)
        return
      }
      const done = await onFinish(encodeCredential(credential))
      if (!done.ok) {
        setError(messageFor(done.error))
        setLoading(false)
        return
      }
      onDone()
    } catch {
      // The user cancelled the browser prompt, or the authenticator failed/timed out.
      setError(
        mode === "register"
          ? "Passkey setup was cancelled or didn’t complete. Please try again."
          : "Passkey sign-in was cancelled or didn’t complete. Please try again.",
      )
      setLoading(false)
    }
  }

  const heading = mode === "register" ? "Set up a passkey" : "Use your passkey"
  const subtext =
    mode === "register"
      ? "Register a passkey — your device’s fingerprint, face, or security key — as a phishing-resistant second factor."
      : "Confirm it’s you with the passkey saved on this device or a security key."
  const buttonLabel = mode === "register" ? "Create passkey" : "Verify with passkey"
  const loadingLabel = mode === "register" ? "Registering" : "Verifying"

  return (
    <>
      <StepIcon>
        <MfaIcon />
      </StepIcon>
      <Heading>{heading}</Heading>
      <Subtext>{subtext}</Subtext>

      {!supported ? (
        <p className="mt-3.5 flex items-center justify-center gap-[5px] text-[12.5px] font-medium text-ao-error">
          <AlertCircleIcon className="size-[13px]" />
          <span>This browser doesn’t support passkeys.</span>
        </p>
      ) : (
        <>
          <PrimaryButton type="button" onClick={run} loading={loading} loadingLabel={loadingLabel}>
            {buttonLabel}
          </PrimaryButton>

          {error && (
            <p className="mt-3.5 flex items-center justify-center gap-[5px] text-[12.5px] font-medium text-ao-error">
              <AlertCircleIcon className="size-[13px]" />
              <span>{error}</span>
            </p>
          )}
        </>
      )}

      {altLabel && onAlt && (
        <p className="mt-[18px] text-center">
          <LinkButton onClick={onAlt}>{altLabel}</LinkButton>
        </p>
      )}

      <BackLink onClick={onBack} />
    </>
  )
}

function messageFor(code: string): string {
  switch (code) {
    case "session_invalid":
      return "Your session has expired. Please sign in again."
    default:
      return "That didn’t work. Please try again."
  }
}
