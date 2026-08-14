import { NextRequest, NextResponse } from "next/server"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie, serializeSessionCookie, sessionCookieOptions } from "@/lib/session-cookie"

// POST /api/login/verify — TOTP MFA challenge. Proxies POST /mfa/verify with the
// session bearer and rotates the session cookie on success. The interactive login
// flow submits through the verify Server Action (basePath/cookie-safe); this route
// is the stable BFF surface for non-action callers.
export async function POST(req: NextRequest) {
  const host = req.headers.get("host") ?? ""
  const cookie = parseSessionCookie(req.cookies.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return NextResponse.json({ error: "session_invalid" }, { status: 401 })
  }

  let code = ""
  try {
    const body = (await req.json()) as { code?: unknown }
    if (typeof body.code === "string") code = body.code
  } catch {
    // empty / non-JSON body → treated as an empty code (gateway rejects generically)
  }

  const { status, data } = await callLoginAPI("/mfa/verify", { host, token: cookie.token, body: { code } })
  if (status !== 200 || typeof data.sessionToken !== "string") {
    return NextResponse.json(
      { error: typeof data.error === "string" ? data.error : "verify_failed" },
      { status: status || 400 },
    )
  }

  const res = NextResponse.json({ ok: true })
  res.cookies.set(SESSION_COOKIE, serializeSessionCookie(cookie.sid, data.sessionToken), sessionCookieOptions)
  return res
}
