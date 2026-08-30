"use client"

import * as React from "react"
import { REGEXP_ONLY_DIGITS } from "input-otp"
import { QRCodeSVG } from "qrcode.react"

import { cn } from "@/lib/utils"
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp"
import {
  BackLink,
  Divider,
  Heading,
  PrimaryButton,
  SsoButton,
  StepIcon,
  Subtext,
} from "../parts"
import { AlertCircleIcon, MfaIcon, PasskeyIcon } from "../icons"
import { mfaMessageForError } from "@/lib/login-client"

type StartResult = { ok: true; secret: string; otpauthUri: string } | { ok: false; error: string }
type ActivateResult = { ok: true; recoveryCodes: string[] } | { ok: false; error: string }

// Which half of the screen the person is on. The choice is always reversible:
// the authenticator view goes back to the chooser, and the chooser still offers
// the passkey.
type Choice = "choose" | "otp"

// StepMfaEnroll is the forced enrolment of the sign-in. The MFA Requirement
// governs the person, they hold no Second Factor, and they enrol one here.
//
// Both Factors are offered, the Passkey first. A device with no authenticator
// must never dead-end, so the authenticator app stays on the screen at all
// times, and a browser that cannot run the ceremony reads the passkey control
// disabled beside a reason. The control is never hidden: a person who sees no
// control cannot tell a missing feature from a broken page.
//
// A person who abandons the passkey prompt lands back on the chooser with the
// authenticator app still there. A cancel is a choice and not a failure, so
// nothing is shown for it.
export function StepMfaEnroll({
  passkeySupported,
  onEnrollPasskey,
  onAbandonPasskey,
  onStart,
  onActivate,
  onDone,
  onBack,
}: {
  /** Whether this browser can run the passkey ceremony at all. */
  passkeySupported: boolean
  /** Runs the whole passkey enrolment. Resolves to an error message to display,
   *  "" when the person cancelled, or null on success (the parent navigates
   *  forward, unmounting this step). */
  onEnrollPasskey: () => Promise<string | null>
  /** Aborts a browser prompt that is still open. The person switched to the
   *  authenticator app, and this screen stays mounted, so nothing else closes
   *  the sheet the device put over it. */
  onAbandonPasskey: () => void
  onStart: () => Promise<StartResult>
  onActivate: (code: string) => Promise<ActivateResult>
  onDone: () => void
  onBack: () => void
}) {
  const [choice, setChoice] = React.useState<Choice>("choose")
  const [uri, setUri] = React.useState<string | null>(null)
  const [secret, setSecret] = React.useState("")
  const [code, setCode] = React.useState("")
  const [codes, setCodes] = React.useState<string[] | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)
  const started = React.useRef(false)

  // The pending secret is minted when the person picks the authenticator app,
  // and once only. A person who enrols a passkey never writes one.
  React.useEffect(() => {
    if (choice !== "otp" || started.current) return
    started.current = true
    onStart().then(
      (r) => {
        if (r.ok) {
          setUri(r.otpauthUri)
          setSecret(r.secret)
          return
        }
        // The guard is released on every failure, so leaving this view and
        // picking the authenticator again asks for a fresh secret. A guard that
        // stayed set would leave the person on a panel that never loads.
        started.current = false
        setError(mfaMessageForError(r.error))
      },
      () => {
        started.current = false
        setError(mfaMessageForError(""))
      },
    )
  }, [choice, onStart])

  async function handlePasskey() {
    if (loading || !passkeySupported) return
    setError(null)
    setLoading(true)
    try {
      const err = await onEnrollPasskey()
      if (err === null) return // Success. The parent navigates and unmounts this.
      // A cancel answers the empty string. The person is back on the chooser,
      // and the authenticator app is still beside the passkey.
      setError(err || null)
    } catch {
      // A Server Action that never answered. The screen must come back either
      // way: a button left loading would take the authenticator app down with
      // it, which is the dead-end this screen exists to prevent.
      setError(mfaMessageForError(""))
    }
    setLoading(false)
  }

  // chooseAuthenticator moves to the authenticator app, whatever the passkey
  // half was doing. The prompt is closed, the press is released, and the
  // refusal of the ceremony the person walked away from is not shown.
  function chooseAuthenticator() {
    onAbandonPasskey()
    setError(null)
    setLoading(false)
    setChoice("otp")
  }

  async function handleActivate(e: React.FormEvent) {
    e.preventDefault()
    if (loading) return
    if (code.length < 6) {
      setError("Please enter all 6 digits.")
      return
    }
    setError(null)
    setLoading(true)
    const r = await onActivate(code)
    setLoading(false)
    if (r.ok) {
      setCodes(r.recoveryCodes)
    } else {
      setError(mfaMessageForError(r.error))
      setCode("")
    }
  }

  // ── Recovery-codes screen (shown once, after activation) ──
  if (codes) {
    return (
      <>
        <StepIcon>
          <MfaIcon />
        </StepIcon>
        <Heading>Save your recovery codes</Heading>
        <Subtext>
          Store these somewhere safe. Each code works <strong>once</strong> if you lose your
          authenticator — they won’t be shown again.
        </Subtext>

        <ul className="my-5 grid grid-cols-2 gap-2 rounded-[10px] border-[1.5px] border-input bg-ao-field p-4 font-mono text-[14px] text-ao-ink">
          {codes.map((c) => (
            <li key={c} className="text-center tracking-wide tabular-nums select-all">
              {c}
            </li>
          ))}
        </ul>

        <PrimaryButton type="button" onClick={onDone}>
          I’ve saved my codes
        </PrimaryButton>
      </>
    )
  }

  const invalid = Boolean(error)

  // ── The chooser. Both Factors, the passkey first. ──
  if (choice === "choose") {
    return (
      <>
        <StepIcon>
          <MfaIcon />
        </StepIcon>
        <Heading>Set up two-factor authentication</Heading>
        <Subtext>
          Your organization requires a second step when you sign in. Choose how you want to
          confirm it’s you.
        </Subtext>

        <PrimaryButton
          type="button"
          onClick={handlePasskey}
          loading={loading}
          loadingLabel="Waiting for your device"
          disabled={!passkeySupported || loading}
          autoFocus
        >
          Set up a passkey
        </PrimaryButton>

        <p className="mt-2.5 text-center text-[12.5px] text-pretty text-ao-muted">
          {passkeySupported
            ? "Your fingerprint, face, screen lock, or security key. Nothing is typed, and your passkey never leaves your device."
            : "This browser cannot use passkeys. Set up an authenticator app instead."}
        </p>

        {invalid && (
          <p
            role="alert"
            className="mt-3.5 flex items-center justify-center gap-[5px] text-[12.5px] font-medium text-ao-error"
          >
            <AlertCircleIcon className="size-[13px]" />
            <span>{error}</span>
          </p>
        )}

        <Divider>or</Divider>

        <SsoButton icon={<MfaIcon className="size-[18px]" />} onClick={chooseAuthenticator}>
          Use an authenticator app
        </SsoButton>

        <p className="mt-[18px] flex items-start gap-[6px] rounded-[10px] border-[1.5px] border-input bg-ao-field p-3 text-[12.5px] text-pretty text-ao-muted">
          <PasskeyIcon className="mt-px size-[14px] shrink-0" />
          <span>
            If a passkey is the only way you sign in and you lose the device, an administrator
            is the only way back into your account.
          </span>
        </p>

        <BackLink onClick={onBack} />
      </>
    )
  }

  // ── The authenticator app. ──
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
      <Heading>Set up two-factor authentication</Heading>
      <Subtext>
        Scan this QR code with your authenticator app, then enter the 6-digit code it shows.
      </Subtext>

      <div className="my-5 flex flex-col items-center gap-3">
        {uri ? (
          <div className="rounded-[12px] border-[1.5px] border-input bg-white p-3">
            <QRCodeSVG value={uri} size={168} marginSize={0} />
          </div>
        ) : (
          <div className="grid h-[192px] w-[192px] place-items-center rounded-[12px] border-[1.5px] border-input bg-ao-field text-[13px] text-ao-muted">
            {error ? "Couldn’t start setup" : "Loading…"}
          </div>
        )}
        {secret && (
          <p className="text-center text-[12.5px] text-ao-muted">
            Can’t scan? Enter this key:{" "}
            <span className="font-mono font-semibold tracking-wide text-ao-ink select-all">{secret}</span>
          </p>
        )}
      </div>

      <form onSubmit={handleActivate} noValidate>
        <InputOTP
          maxLength={6}
          pattern={REGEXP_ONLY_DIGITS}
          value={code}
          onChange={(v) => {
            setCode(v)
            if (error) setError(null)
          }}
          aria-invalid={invalid}
          disabled={!uri}
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

        <PrimaryButton loading={loading} loadingLabel="Verifying">
          Turn on two-factor
        </PrimaryButton>
      </form>

      <BackLink
        onClick={() => {
          setError(null)
          setChoice("choose")
        }}
      >
        Other options
      </BackLink>
    </>
  )
}
