"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

export type PasswordResult = { ok: true; methods: string[] } | { ok: false; error: string }

// Server Action for the password step. Called from the client, it POSTs to the
// current route (basePath-aware), verifies the password against the session's
// bound user, and rotates the cookie to the new token on success.
export async function submitPassword(password: string): Promise<PasswordResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }

  const host = (await headers()).get("host") ?? ""

  // The password step never names the authorization request: the gateway does
  // not touch the authn session here. The carried authRequest reaches the
  // gateway at the finalize step, in /complete.
  const { status, data } = await callLoginAPI("/password", {
    host,
    token: cookie.token,
    body: { password: password ?? "" },
  })

  if (status !== 200 || typeof data.sessionToken !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "password_failed" }
  }

  cookieStore.set(
    SESSION_COOKIE,
    serializeSessionCookie(cookie.sid, data.sessionToken),
    sessionCookieOptions,
  )

  return { ok: true, methods: Array.isArray(data.methods) ? (data.methods as string[]) : [] }
}
