"use client"

import * as React from "react"
import Link from "next/link"

import { Heading, PrimaryButton, StepIcon, Subtext, TextField } from "@/components/login/parts"
import { LockIcon, SuccessCheckIcon } from "@/components/login/icons"
import { changePassword } from "@/lib/recovery-actions"
import { recoveryErrorMessage } from "@/lib/recovery-messages"
import { useLoginFlow } from "@/components/login/flow-context"

const MIN_LENGTH = 8

export default function ChangePasswordPage() {
  // When we got here mid-login (a forced change during finalize), a pending
  // authRequest is still carried; resume finalize at /success — the flag is now
  // cleared, so /complete succeeds. Otherwise this was a standalone change.
  const { authRequest } = useLoginFlow()
  const continueHref = authRequest ? "/success" : "/identifier"
  const [current, setCurrent] = React.useState("")
  const [next, setNext] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)
  const [done, setDone] = React.useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (loading) return
    if (next.length < MIN_LENGTH) {
      setError(`Your new password must be at least ${MIN_LENGTH} characters`)
      return
    }
    if (next !== confirm) {
      setError("The new passwords don’t match")
      return
    }
    setError(null)
    setLoading(true)
    const result = await changePassword(current, next)
    if (result.ok) {
      setDone(true)
      return
    }
    setError(recoveryErrorMessage(result.error))
    setLoading(false)
  }

  if (done) {
    return (
      <>
        <StepIcon ok>
          <SuccessCheckIcon />
        </StepIcon>
        <Heading>Password updated</Heading>
        <Subtext>Your password has been changed. You can continue signing in.</Subtext>
        <div className="flex justify-center">
          <Link
            href={continueHref}
            className="text-[13.5px] font-medium text-ao-muted transition-colors hover:text-ao-orange"
          >
            Continue
          </Link>
        </div>
      </>
    )
  }

  return (
    <>
      <Heading>Change your password</Heading>
      <Subtext>Enter your current password and choose a new one.</Subtext>

      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-[18px]">
        <TextField
          id="current"
          type="password"
          label="Current password"
          autoComplete="current-password"
          autoFocus
          icon={<LockIcon />}
          value={current}
          onChange={(e) => {
            setCurrent(e.target.value)
            if (error) setError(null)
          }}
        />
        <TextField
          id="next"
          type="password"
          label="New password"
          autoComplete="new-password"
          icon={<LockIcon />}
          value={next}
          onChange={(e) => {
            setNext(e.target.value)
            if (error) setError(null)
          }}
        />
        <TextField
          id="confirm"
          type="password"
          label="Confirm new password"
          autoComplete="new-password"
          icon={<LockIcon />}
          error={error}
          value={confirm}
          onChange={(e) => {
            setConfirm(e.target.value)
            if (error) setError(null)
          }}
        />
        <PrimaryButton loading={loading} loadingLabel="Updating">
          Update password
        </PrimaryButton>
      </form>
    </>
  )
}
