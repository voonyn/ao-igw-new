"use client"

import * as React from "react"
import Link from "next/link"

import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import {
  BackLink,
  Heading,
  PrimaryButton,
  Subtext,
  TextField,
} from "../parts"
import { AccountChip } from "../account-chip"
import { EyeIcon, LockIcon } from "../icons"

export function StepPassword({
  email,
  onBack,
  onSubmit,
}: {
  email: string
  onBack: () => void
  /** Resolves to an error message to display, or null on success (the parent
   *  navigates forward, unmounting this component). */
  onSubmit: (password: string) => Promise<string | null>
}) {
  const [password, setPassword] = React.useState("")
  const [show, setShow] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (loading) return
    if (!password) {
      setError("Please enter your password")
      document.getElementById("password")?.focus()
      return
    }
    setError(null)
    setLoading(true)
    const err = await onSubmit(password)
    if (err) {
      setError(err)
      setLoading(false)
    }
  }

  return (
    <>
      <AccountChip email={email} onChange={onBack} />

      <Heading>Enter your password</Heading>
      <Subtext>
        Signing in to <strong>AlphaOmega</strong>
      </Subtext>

      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-[18px]">
        <TextField
          id="password"
          name="password"
          type={show ? "text" : "password"}
          label="Password"
          placeholder="Enter your password"
          autoComplete="current-password"
          autoFocus
          icon={<LockIcon />}
          error={error}
          value={password}
          onChange={(e) => {
            setPassword(e.target.value)
            if (error) setError(null)
          }}
          trailing={
            <button
              type="button"
              onClick={() => setShow((s) => !s)}
              aria-label={show ? "Hide password" : "Show password"}
              className="absolute right-2 grid size-[34px] place-items-center rounded-lg text-ao-muted transition-colors hover:bg-[var(--ao-orange-soft)] hover:text-ao-orange"
            >
              <EyeIcon off={show} />
            </button>
          }
        />

        <div className="-mt-0.5 flex items-center justify-between">
          <Label
            htmlFor="remember"
            className="flex cursor-pointer items-center gap-[9px] text-[13.5px] font-normal text-ao-label select-none"
          >
            <Checkbox
              id="remember"
              className="size-[18px] rounded-[5px] border-[1.5px] border-ao-muted-2"
            />
            Remember this device
          </Label>
          <Link
            href="/forgot"
            className="rounded-none text-[13.5px] font-medium text-primary transition-colors hover:text-ao-orange-bright hover:underline"
          >
            Forgot password?
          </Link>
        </div>

        <PrimaryButton loading={loading} loadingLabel="Signing in">
          Sign In
        </PrimaryButton>
      </form>

      <BackLink onClick={onBack} />
    </>
  )
}
