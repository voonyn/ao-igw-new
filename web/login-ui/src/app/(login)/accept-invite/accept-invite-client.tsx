"use client"

import * as React from "react"
import Link from "next/link"

import { Heading, PrimaryButton, StepIcon, Subtext, TextField } from "@/components/login/parts"
import { LockIcon, SuccessCheckIcon } from "@/components/login/icons"
import { acceptInvitation } from "@/lib/recovery-actions"
import { recoveryErrorMessage } from "@/lib/recovery-messages"

const MIN_LENGTH = 8

// Mirrors ResetClient: the two flows are the same shape (token + new password),
// differing only in that this one activates a StateInitial account. It does not
// hand off to /success — that screen requires a live session, and the invitee has
// none until they sign in with the password they just chose.
export function AcceptInviteClient({ token }: { token: string }) {
  const [password, setPassword] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)
  const [done, setDone] = React.useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (loading) return
    if (password.length < MIN_LENGTH) {
      setError(`Your password must be at least ${MIN_LENGTH} characters`)
      return
    }
    if (password !== confirm) {
      setError("The passwords don’t match")
      return
    }
    setError(null)
    setLoading(true)
    const result = await acceptInvitation(token, password)
    if (result.ok) {
      setDone(true)
      return
    }
    setError(recoveryErrorMessage(result.error))
    setLoading(false)
  }

  if (!token) {
    return (
      <>
        <Heading>Invalid invitation link</Heading>
        <Subtext>
          This link is missing its token. Please ask whoever invited you to send a new invitation.
        </Subtext>
      </>
    )
  }

  if (done) {
    return (
      <>
        <StepIcon ok>
          <SuccessCheckIcon />
        </StepIcon>
        <Heading>Account activated</Heading>
        <Subtext>Your password has been set. You can now sign in with it.</Subtext>
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
      <Heading>Accept your invitation</Heading>
      <Subtext>Choose a password to activate your account.</Subtext>

      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-[18px]">
        <TextField
          id="password"
          type="password"
          label="Password"
          autoComplete="new-password"
          autoFocus
          icon={<LockIcon />}
          value={password}
          onChange={(e) => {
            setPassword(e.target.value)
            if (error) setError(null)
          }}
        />
        <TextField
          id="confirm"
          type="password"
          label="Confirm password"
          autoComplete="new-password"
          icon={<LockIcon />}
          error={error}
          value={confirm}
          onChange={(e) => {
            setConfirm(e.target.value)
            if (error) setError(null)
          }}
        />
        {error ? (
          <Subtext>This invitation link stays valid — you can try a different password.</Subtext>
        ) : null}
        <PrimaryButton loading={loading} loadingLabel="Activating">
          Activate account
        </PrimaryButton>
      </form>
    </>
  )
}
