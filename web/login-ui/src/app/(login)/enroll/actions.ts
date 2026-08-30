"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

export type EnrollStartResult =
  | { ok: true; secret: string; otpauthUri: string }
  | { ok: false; error: string }

export type EnrollActivateResult =
  | { ok: true; recoveryCodes: string[] }
  | { ok: false; error: string }

// startEnrollment generates a pending TOTP secret and returns it plus the
// otpauth:// provisioning URI (the client renders the QR). It records no factor and
// does not rotate the cookie.
export async function startEnrollment(): Promise<EnrollStartResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/mfa/totp/enroll/start", {
    host,
    token: cookie.token,
  })

  if (status !== 200 || typeof data.secret !== "string" || typeof data.otpauthUri !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "enroll_failed" }
  }

  return { ok: true, secret: data.secret, otpauthUri: data.otpauthUri }
}

// activateEnrollment proves the pending secret with a code, activating the factor.
// On success it rotates the cookie (the OTP factor is now recorded) and returns the
// one-time recovery codes, shown to the user exactly once.
export async function activateEnrollment(code: string): Promise<EnrollActivateResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/mfa/totp/enroll/activate", {
    host,
    token: cookie.token,
    body: { code: code ?? "" },
  })

  if (status !== 200 || typeof data.sessionToken !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "enroll_failed" }
  }

  cookieStore.set(
    SESSION_COOKIE,
    serializeSessionCookie(cookie.sid, data.sessionToken),
    sessionCookieOptions,
  )

  const recoveryCodes = Array.isArray(data.recoveryCodes) ? (data.recoveryCodes as string[]) : []
  return { ok: true, recoveryCodes }
}

export type PasskeyEnrollStartResult =
  | { ok: true; options: PublicKeyCredentialCreationOptionsJSON }
  | { ok: false; error: string }

export type PasskeyEnrollFinishResult = { ok: true } | { ok: false; error: string }

// startPasskeyEnrollment asks the gateway for the registration options the
// browser passes to navigator.credentials.create().
//
// The options cross this action whole, and no field of them is read here. Every
// field is part of what the device will sign, so a value this action picked out
// and rebuilt would change what the signature covers.
//
// The call is server to server and sends no browser `Origin`. The gateway keeps
// only the origins the tenant relying party covers, and refuses the ceremony when
// that list is empty.
//
// It records no factor and it does not rotate the cookie.
export async function startPasskeyEnrollment(): Promise<PasskeyEnrollStartResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/mfa/passkey/enroll/start", {
    host,
    token: cookie.token,
  })

  if (status !== 200 || !data.publicKey) {
    return { ok: false, error: typeof data.error === "string" ? data.error : "passkey_failed" }
  }

  return { ok: true, options: data.publicKey as PublicKeyCredentialCreationOptionsJSON }
}

// finishPasskeyEnrollment stores the proved Passkey and rotates the cookie to the
// token the gateway minted.
//
// The answer crosses this action whole, for the same reason the options do. The
// gateway records the `webauthn` factor on the same transaction the Passkey lands
// on, so the person continues straight to the application with no second
// challenge.
//
// A refusal leaves the sign-in alive. The person tries again on the same screen,
// or sets up an authenticator app beside it.
export async function finishPasskeyEnrollment(
  credential: PublicKeyCredentialJSON,
): Promise<PasskeyEnrollFinishResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/mfa/passkey/enroll/finish", {
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
