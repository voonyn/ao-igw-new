"use client"

import * as React from "react"
import Link from "next/link"

import { Heading, PrimaryButton, StepIcon, Subtext, TextField } from "@/components/login/parts"
import { MailIcon, SuccessCheckIcon } from "@/components/login/icons"
import { requestPasswordReset } from "@/lib/recovery-actions"

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export default function ForgotPasswordPage() {
  const [email, setEmail] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)
  const [sent, setSent] = React.useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (loading) return
    const value = email.trim()
    if (!EMAIL_RE.test(value)) {
      setError("Please enter a valid email address")
      return
    }
    setError(null)
    setLoading(true)
    const result = await requestPasswordReset(value)
    // Enumeration-safe: always show the same confirmation when the gateway accepts
    // the request, regardless of whether the account exists.
    if (result.ok) {
      setSent(true)
      return
    }
    setError("Something went wrong. Please try again.")
    setLoading(false)
  }

  if (sent) {
    return (
      <>
        <StepIcon ok>
          <SuccessCheckIcon />
        </StepIcon>
        <Heading>Check your email</Heading>
        <Subtext>
          If an account exists for <strong>{email}</strong>, we’ve sent a link to reset your password.
        </Subtext>
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
      <Heading>Reset your password</Heading>
      <Subtext>Enter your email and we’ll send you a link to reset it.</Subtext>

      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-[18px]">
        <TextField
          id="email"
          name="email"
          type="email"
          label="Email address"
          placeholder="you@company.com"
          autoComplete="email"
          autoFocus
          icon={<MailIcon />}
          error={error}
          value={email}
          onChange={(e) => {
            setEmail(e.target.value)
            if (error) setError(null)
          }}
        />
        <PrimaryButton loading={loading} loadingLabel="Sending">
          Send reset link
        </PrimaryButton>
      </form>

      <div className="mt-[22px] flex justify-center">
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
