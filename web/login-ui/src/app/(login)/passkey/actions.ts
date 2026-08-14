"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

// Server Actions for the WebAuthn/passkey ceremonies (add-webauthn-passkeys). Each
// ceremony is two round-trips: `begin` returns the creation/request options (the
// browser then runs navigator.credentials.create/get), `finish` verifies the
// authenticator response and rotates the session cookie — mirroring submitPassword /
// submitMfaVerify. The raw credential JSON is forwarded verbatim to the gateway's
// go-webauthn parser.

export type BeginResult = { ok: true; publicKey: Record<string, unknown> } | { ok: false; error: string }
export type FinishResult = { ok: true } | { ok: false; error: string }

async function begin(path: string): Promise<BeginResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) return { ok: false, error: "session_invalid" }

  const host = (await headers()).get("host") ?? ""
  const { status, data } = await callLoginAPI(path, { host, token: cookie.token })
  if (status !== 200 || typeof data.publicKey !== "object" || data.publicKey === null) {
    return { ok: false, error: typeof data.error === "string" ? data.error : "passkey_failed" }
  }
  return { ok: true, publicKey: data.publicKey as Record<string, unknown> }
}

async function finish(path: string, credential: unknown): Promise<FinishResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) return { ok: false, error: "session_invalid" }

  const host = (await headers()).get("host") ?? ""
  const { status, data } = await callLoginAPI(path, { host, token: cookie.token, body: credential })
  if (status !== 200 || typeof data.sessionToken !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "passkey_failed" }
  }
  cookieStore.set(SESSION_COOKIE, serializeSessionCookie(cookie.sid, data.sessionToken), sessionCookieOptions)
  return { ok: true }
}

export async function beginPasskeyLogin(): Promise<BeginResult> {
  return begin("/mfa/webauthn/login/begin")
}
export async function finishPasskeyLogin(credential: unknown): Promise<FinishResult> {
  return finish("/mfa/webauthn/login/finish", credential)
}
export async function beginPasskeyRegister(): Promise<BeginResult> {
  return begin("/mfa/webauthn/register/begin")
}
export async function finishPasskeyRegister(credential: unknown): Promise<FinishResult> {
  return finish("/mfa/webauthn/register/finish", credential)
}
