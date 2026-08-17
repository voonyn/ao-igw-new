"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

export type CheckResult = { ok: true; methods: string[] } | { ok: false; error: string }

// Server Action for the identifier step. The browser POSTs to the current route
// (basePath-aware, unlike a client `fetch("/api/...")`), so this always reaches
// Next.js. It mints a session on the gateway and stores the token in the
// HttpOnly cookie — the token never reaches the browser body.
export async function checkIdentifier(identifier: string): Promise<CheckResult> {
  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/identifier", {
    host,
    body: { identifier: identifier ?? "" },
  })

  if (status !== 200 || typeof data.sessionToken !== "string" || typeof data.sessionId !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "check_failed" }
  }

  const cookieStore = await cookies()
  cookieStore.set(
    SESSION_COOKIE,
    serializeSessionCookie(data.sessionId, data.sessionToken),
    sessionCookieOptions,
  )

  return { ok: true, methods: Array.isArray(data.methods) ? (data.methods as string[]) : [] }
}
