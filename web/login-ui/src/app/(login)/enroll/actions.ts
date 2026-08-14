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
