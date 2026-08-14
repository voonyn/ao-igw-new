"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

export type VerifyResult = { ok: true } | { ok: false; error: string }

// Server Action for the MFA challenge. It verifies a TOTP or recovery code against
// the session's bound user and rotates the cookie to the new token on success —
// mirroring submitPassword. The gateway records the OTP factor; a subsequent
// finalize then passes the factor gate.
export async function submitMfaVerify(code: string): Promise<VerifyResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/mfa/verify", {
    host,
    token: cookie.token,
    body: { code: code ?? "" },
  })

  if (status !== 200 || typeof data.sessionToken !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "verify_failed" }
  }

  cookieStore.set(
    SESSION_COOKIE,
    serializeSessionCookie(cookie.sid, data.sessionToken),
    sessionCookieOptions,
  )

  return { ok: true }
}
