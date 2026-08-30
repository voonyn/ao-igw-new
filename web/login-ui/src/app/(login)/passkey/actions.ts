"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

export type ChallengeStartResult =
  | { ok: true; options: PublicKeyCredentialRequestOptionsJSON }
  | { ok: false; error: string }

export type ChallengeFinishResult = { ok: true } | { ok: false; error: string }

// startPasskeyChallenge asks the gateway for the assertion options the browser
// passes to navigator.credentials.get().
//
// The options cross this action whole, and no field of them is read here. Every
// field is part of what the device will sign, so a value this action picked out
// and rebuilt would change what the signature covers.
//
// The call is server to server and sends no browser `Origin`. The gateway keeps
// only the origins the tenant relying party covers, and refuses the ceremony when
// that list is empty.
//
// The gateway spends the shared second-factor guessing budget here, so a start
// can answer `rate_limited`. It records no factor and it does not rotate the
// cookie.
export async function startPasskeyChallenge(): Promise<ChallengeStartResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/mfa/passkey/challenge/start", {
    host,
    token: cookie.token,
  })

  if (status !== 200 || !data.publicKey) {
    return { ok: false, error: typeof data.error === "string" ? data.error : "passkey_failed" }
  }

  return { ok: true, options: data.publicKey as PublicKeyCredentialRequestOptionsJSON }
}

// finishPasskeyChallenge sends the answer the device produced and rotates the
// cookie to the token the gateway minted.
//
// The answer crosses this action whole, for the same reason the options do. The
// gateway records the `webauthn` factor, and a later finalize then passes the
// factor gate.
//
// A refusal leaves the sign-in alive. The person answers again on the same
// screen, or picks the other Second Factor.
export async function finishPasskeyChallenge(
  credential: PublicKeyCredentialJSON,
): Promise<ChallengeFinishResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/mfa/passkey/challenge/finish", {
    host,
    token: cookie.token,
    body: { credential },
  })

  if (status !== 200 || typeof data.sessionToken !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "passkey_failed" }
  }

  cookieStore.set(
    SESSION_COOKIE,
    serializeSessionCookie(cookie.sid, data.sessionToken),
    sessionCookieOptions,
  )

  return { ok: true }
}
