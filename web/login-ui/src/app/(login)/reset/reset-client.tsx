"use client"

import * as React from "react"
import Link from "next/link"

import { Heading, PrimaryButton, StepIcon, Subtext, TextField } from "@/components/login/parts"
import { LockIcon, SuccessCheckIcon } from "@/components/login/icons"
import { confirmPasswordReset } from "@/lib/recovery-actions"
import { recoveryErrorMessage } from "@/lib/recovery-messages"

const MIN_LENGTH = 8

export function ResetClient({ token }: { token: string }) {
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
    const result = await confirmPasswordReset(token, password)
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
        <Heading>Invalid reset link</Heading>
        <Subtext>This link is missing its token. Please request a new password reset.</Subtext>
        <div className="flex justify-center">
          <Link
            href="/forgot"
            className="text-[13.5px] font-medium text-primary transition-colors hover:text-ao-orange-bright hover:underline"
          >
            Request a new link
          </Link>
        </div>
      </>
    )
  }

  if (done) {
    return (
      <>
        <StepIcon ok>
          <SuccessCheckIcon />
        </StepIcon>
        <Heading>Password reset</Heading>
        <Subtext>Your password has been updated. You can now sign in with it.</Subtext>
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

  return (
    <>
      <Heading>Choose a new password</Heading>
      <Subtext>Enter and confirm your new password.</Subtext>

      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-[18px]">
        <TextField
          id="password"
          type="password"
          label="New password"
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
        <PrimaryButton loading={loading} loadingLabel="Saving">
          Reset password
        </PrimaryButton>
      </form>
    </>
  )
}
