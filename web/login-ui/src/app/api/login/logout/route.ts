import { NextRequest, NextResponse } from "next/server"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

// POST /api/login/logout — terminates the session on the gateway (best effort)
// and clears the cookie in the same response. Idempotent: a missing or dead
// cookie still clears and returns ok.
export async function POST(req: NextRequest) {
  const host = req.headers.get("host") ?? ""
  const cookie = parseSessionCookie(req.cookies.get(SESSION_COOKIE)?.value)

  if (cookie) {
    await callLoginAPI("/logout", { host, token: cookie.token })
  }

  const res = NextResponse.json({ status: "ok" })
  res.cookies.set(SESSION_COOKIE, "", { ...sessionCookieOptions, maxAge: 0 })
  return res
}
