"use client"

import * as React from "react"
import Link from "next/link"

import { Heading, StepIcon, Subtext } from "@/components/login/parts"
import { SuccessCheckIcon } from "@/components/login/icons"
import { confirmEmailVerification } from "@/lib/recovery-actions"
import { recoveryErrorMessage } from "@/lib/recovery-messages"

type State = { kind: "loading" } | { kind: "ok" } | { kind: "error"; message: string }

export function VerifyEmailClient({ token }: { token: string }) {
  // A missing token is a pure render outcome, not an effect — start in the error
  // state so the effect only ever runs the async confirm (avoids a synchronous
  // setState inside the effect body).
  const [state, setState] = React.useState<State>(() =>
    token ? { kind: "loading" } : { kind: "error", message: "This link is missing its token." },
  )
  // Guard against React StrictMode double-invoke in development.
  const ran = React.useRef(false)

  React.useEffect(() => {
    if (!token || ran.current) return
    ran.current = true
    confirmEmailVerification(token).then((result) => {
      setState(result.ok ? { kind: "ok" } : { kind: "error", message: recoveryErrorMessage(result.error) })
    })
  }, [token])

  if (state.kind === "loading") {
    return (
      <>
        <Heading>Verifying your email…</Heading>
        <Subtext>One moment while we confirm your verification link.</Subtext>
      </>
    )
  }

  if (state.kind === "ok") {
    return (
      <>
        <StepIcon ok>
          <SuccessCheckIcon />
        </StepIcon>
        <Heading>Email verified</Heading>
        <Subtext>Your email address has been confirmed.</Subtext>
        <div className="flex justify-center">
          <Link
            href="/identifier"
            className="text-[13.5px] font-medium text-ao-muted transition-colors hover:text-ao-orange"
          >
            Continue to sign in
          </Link>
        </div>
      </>
    )
  }

  return (
    <>
      <Heading>Verification failed</Heading>
      <Subtext>{state.message}</Subtext>
      <div className="flex justify-center">
        <Link
          href="/identifier"
          className="text-[13.5px] font-medium text-ao-muted transition-colors hover:text-ao-orange"
        >
          Back to sign in
        </Link>
      </div>
    </>
  )
}
