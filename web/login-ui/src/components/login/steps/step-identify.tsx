"use client"

import * as React from "react"

import {
  Divider,
  Footer,
  Heading,
  PrimaryButton,
  SsoButton,
  Subtext,
  TextField,
} from "../parts"
import { GoogleIcon, MailIcon, MicrosoftIcon } from "../icons"

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function StepIdentify({
  initialEmail,
  onContinue,
}: {
  initialEmail: string
  /** Resolves to an error message to display, or null on success (the parent
   *  navigates forward, so this component unmounts and loading is not reset). */
  onContinue: (email: string) => Promise<string | null>
}) {
  const [email, setEmail] = React.useState(initialEmail)
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (loading) return
    const value = email.trim()
    if (!value) {
      setError("Please enter your email address")
      document.getElementById("email")?.focus()
      return
    }
    if (!EMAIL_RE.test(value)) {
      setError("Please enter a valid email address")
      document.getElementById("email")?.focus()
      return
    }
    setError(null)
    setLoading(true)
    const err = await onContinue(value)
    if (err) {
      setError(err)
      setLoading(false)
    }
  }

  return (
    <>
      <Heading>Welcome back</Heading>
      <Subtext>Sign in to your organization’s portal</Subtext>

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
        <PrimaryButton loading={loading} loadingLabel="Checking">
          Continue
        </PrimaryButton>
      </form>

      <Divider>or continue with</Divider>

      <div className="grid grid-cols-2 gap-3">
        <SsoButton icon={<GoogleIcon />}>Google</SsoButton>
        <SsoButton icon={<MicrosoftIcon />}>Microsoft</SsoButton>
      </div>

      <Footer />
    </>
  )
}
