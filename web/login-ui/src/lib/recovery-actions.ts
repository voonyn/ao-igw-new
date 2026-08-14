"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie } from "@/lib/session-cookie"

// Server Actions for the account-recovery flows. Each POSTs to the current route
// (basePath-aware, unlike a client `fetch("/api/...")`) and forwards to the Go
// login API through callLoginAPI, which attaches the server-only PAT. Tokens and
// passwords never reach the browser bundle.

export type RecoveryResult = { ok: true } | { ok: false; error: string }

async function post(path: string, body: unknown, token?: string): Promise<RecoveryResult> {
  const host = (await headers()).get("host") ?? ""
  const { status, data } = await callLoginAPI(path, { host, token, body })
  if (status !== 200) {
    return { ok: false, error: typeof data.error === "string" ? data.error : "request_failed" }
  }
  return { ok: true }
}

// requestPasswordReset is enumeration-safe: the gateway returns 200 whether or
// not the identifier resolves, so a success here reveals nothing about the account.
export async function requestPasswordReset(identifier: string): Promise<RecoveryResult> {
  return post("/password/reset/request", { identifier: identifier ?? "" })
}

export async function confirmPasswordReset(token: string, password: string): Promise<RecoveryResult> {
  return post("/password/reset/confirm", { token: token ?? "", password: password ?? "" })
}

// acceptInvitation sets the invitee's first password and activates the account.
// A rejected password leaves the invite token usable, so the link keeps working
// after a policy failure.
export async function acceptInvitation(token: string, password: string): Promise<RecoveryResult> {
  return post("/invitation/accept", { token: token ?? "", password: password ?? "" })
}

export async function requestEmailVerification(identifier: string): Promise<RecoveryResult> {
  return post("/email/verify/request", { identifier: identifier ?? "" })
}

export async function confirmEmailVerification(token: string): Promise<RecoveryResult> {
  return post("/email/verify/confirm", { token: token ?? "" })
}

// changePassword requires the authenticated session cookie; the gateway verifies
// the current password before applying the new one.
export async function changePassword(currentPassword: string, newPassword: string): Promise<RecoveryResult> {
  const cookie = parseSessionCookie((await cookies()).get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }
  return post(
    "/password/change",
    { currentPassword: currentPassword ?? "", newPassword: newPassword ?? "" },
    cookie.token,
  )
}
