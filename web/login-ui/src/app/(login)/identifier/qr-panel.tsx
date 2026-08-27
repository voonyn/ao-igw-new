"use client"

import * as React from "react"
import { QRCodeSVG } from "qrcode.react"

import { Footer, Heading, PrimaryButton, Subtext } from "@/components/login/parts"
import { useLoginFlow } from "@/components/login/flow-context"
import {
  pollQRLogin,
  startQRLogin,
  type PollStatus,
  type QRCode,
  type StartQRResult,
} from "./qr-actions"

// How often the browser asks the gateway what happened to the scan.
const POLL_MS = 2000

/** field reads a string off the code object of the verifier, and answers an
 *  empty string for anything else. The object is third-party, so no field is
 *  assumed to be there. */
function field(qr: QRCode, key: string): string {
  const value = qr[key]
  return typeof value === "string" ? value : ""
}

/** clock renders the remaining seconds as m:ss. */
function clock(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, "0")}`
}

/**
 * QRPanel is the scan tab of the sign-in page.
 *
 * It holds the attempt counter and nothing else. The counter is the key of the
 * session below, so "Start again" remounts it. A remount is what cancels the
 * poll of the dead transaction and clears every piece of its state at once.
 */
export function QRPanel() {
  const [attempt, setAttempt] = React.useState(0)
  return <QRSession key={attempt} onRestart={() => setAttempt((n) => n + 1)} />
}

/**
 * QRSession opens one transaction, shows the code the Scan Verifier supplied,
 * and polls until the scan signs the person in.
 *
 * A scan that succeeds lands in the flow where a password lands: the login
 * session is authenticated and the browser goes to /success.
 *
 * Everything that is not a success reads the same. The gateway answers only
 * pending, authenticated, or expired, so a refused scan and a timed-out one tell
 * the person the same thing: start again.
 */
function QRSession({ onRestart }: { onRestart: () => void }) {
  const { navigate } = useLoginFlow()
  const [qr, setQR] = React.useState<QRCode | null>(null)
  const [secondsLeft, setSecondsLeft] = React.useState(0)
  const [expired, setExpired] = React.useState(false)
  const [failed, setFailed] = React.useState(false)

  React.useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const poll = async () => {
      // A Server Action throws when the network drops. That is not an answer
      // about the scan, so the loop keeps waiting. The countdown below still
      // ends the wait, so this cannot spin forever.
      let status: PollStatus
      try {
        status = await pollQRLogin()
      } catch {
        timer = setTimeout(poll, POLL_MS)
        return
      }
      if (cancelled) return
      if (status === "authenticated") {
        navigate("/success", "forward")
        return
      }
      if (status === "expired") {
        setExpired(true)
        return
      }
      timer = setTimeout(poll, POLL_MS)
    }

    void (async () => {
      let started: StartQRResult
      try {
        started = await startQRLogin()
      } catch {
        if (!cancelled) setFailed(true)
        return
      }
      if (cancelled) return
      if (!started.ok) {
        setFailed(true)
        return
      }
      setQR(started.qrCode)
      setSecondsLeft(started.expiresIn)
      timer = setTimeout(poll, POLL_MS)
    })()

    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [navigate])

  // The countdown. It runs only while a live code is on screen.
  React.useEffect(() => {
    if (!qr || expired || secondsLeft <= 0) return
    const tick = setTimeout(() => setSecondsLeft((left) => left - 1), 1000)
    return () => clearTimeout(tick)
  }, [qr, expired, secondsLeft])

  // A code whose countdown reached zero is dead, whatever the poll says next. A
  // person must never wait on a code that cannot work.
  const dead = expired || (qr !== null && secondsLeft <= 0)

  if (failed || dead) {
    return (
      <>
        <Heading>{failed ? "Something went wrong" : "That code expired"}</Heading>
        <Subtext>
          {failed
            ? "The code could not be created. Please try again."
            : "A code is short-lived. Start again to get a new one."}
        </Subtext>
        <PrimaryButton type="button" onClick={onRestart}>
          Start again
        </PrimaryButton>
        <Footer />
      </>
    )
  }

  const url = qr ? field(qr, "url") : ""
  const fallback = qr ? field(qr, "fallback_url") : ""

  return (
    <>
      <Heading>Scan to sign in</Heading>
      <Subtext>Open your wallet app and scan this code</Subtext>

      <div className="flex flex-col items-center gap-4">
        <div className="rounded-[10px] border-[1.5px] border-input bg-white p-4">
          {url ? (
            <QRCodeSVG value={url} size={192} title="Sign-in code" />
          ) : (
            <div className="flex size-48 items-center justify-center">
              <span className="ao-spinner" />
            </div>
          )}
        </div>

        {qr ? (
          <p aria-live="polite" className="text-[12.5px] text-ao-muted">
            This code expires in {clock(secondsLeft)}
          </p>
        ) : null}

        {fallback ? (
          <a
            href={fallback}
            target="_blank"
            rel="noreferrer noopener"
            className="text-[13.5px] font-medium text-primary transition-colors hover:text-ao-orange-bright hover:underline"
          >
            No app yet? Get the wallet
          </a>
        ) : null}
      </div>

      <Footer />
    </>
  )
}
