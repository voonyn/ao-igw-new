"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

/** The code object of the Scan Verifier, carried through unchanged. The page
 *  reads `url` for the code and `fallback_url` for the "no app?" link, and any
 *  other field the verifier adds survives the trip. */
export type QRCode = Record<string, unknown>

export type StartQRResult =
  | { ok: true; qrCode: QRCode; expiresIn: number }
  | { ok: false; error: string }

/**
 * startQRLogin opens a QR Login transaction and stores the login session token
 * in the HttpOnly cookie. The token never reaches the browser body, the same way
 * it does not at the identifier step.
 *
 * ponytail: opening the scan tab overwrites the cookie, so a person who was
 * already signed in and only looked at the tab loses that session. Typing an
 * email and pressing Continue costs them the same session, so the scan tab is no
 * worse than the page already is. Defer the start behind a "Show code" button
 * the day a live session must survive a look.
 */
export async function startQRLogin(): Promise<StartQRResult> {
  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/qr/start", { host })

  if (
    status !== 200 ||
    typeof data.sessionToken !== "string" ||
    typeof data.sessionId !== "string" ||
    data.qrCode === null ||
    typeof data.qrCode !== "object"
  ) {
    return { ok: false, error: typeof data.error === "string" ? data.error : "qr_start_failed" }
  }

  const cookieStore = await cookies()
  cookieStore.set(
    SESSION_COOKIE,
    serializeSessionCookie(data.sessionId, data.sessionToken),
    sessionCookieOptions,
  )

  return {
    ok: true,
    qrCode: data.qrCode as QRCode,
    expiresIn: typeof data.expiresIn === "number" ? data.expiresIn : 0,
  }
}

/** pending: keep waiting. authenticated: the person is signed in. expired: the
 *  code is dead, and the remedy is to start again. The gateway answers nothing
 *  else, so a refused scan and a timed-out one read alike. */
export type PollStatus = "pending" | "authenticated" | "expired"

/**
 * pollQRLogin reports the state of the transaction. On the one poll that turns
 * the login session authenticated, the gateway rotates the token, so the cookie
 * is rewritten here with the new one.
 */
export async function pollQRLogin(): Promise<PollStatus> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) return "expired"

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/qr/poll", { host, token: cookie.token })
  if (status !== 200) return "expired"

  if (data.status === "authenticated") {
    if (typeof data.sessionToken === "string") {
      cookieStore.set(
        SESSION_COOKIE,
        serializeSessionCookie(cookie.sid, data.sessionToken),
        sessionCookieOptions,
      )
    }
    return "authenticated"
  }

  return data.status === "pending" ? "pending" : "expired"
}
