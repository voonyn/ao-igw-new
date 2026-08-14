/**
 * Server-only client for the Go login API (/api/v1/login/*).
 *
 * It attaches the backend PAT (AO_LOGIN_UI_PAT) as X-Login-UI-PAT, forwards
 * the browser's auth domain as X-Forwarded-Host so the gateway resolves the
 * tenant, and forwards the end user's address as X-Forwarded-For so the
 * gateway's per-IP rate-limit dimension is live. Both credentials live only
 * here, in server code — never in the client bundle. AO_API_URL mirrors
 * proxy.ts.
 */

import { headers as requestHeaders } from "next/headers"

const GO_API = process.env.AO_API_URL ?? "http://localhost:8080"
const PAT = process.env.AO_LOGIN_UI_PAT ?? ""

const IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/
const IPV6 = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i

/**
 * clientIP returns the end user's address as read off the request currently
 * being handled — never the BFF's own socket. A single shared value would put
 * every login in the world into one bucket, which is worse than sending
 * nothing, so anything absent or unparseable yields undefined and the gateway
 * skips the dimension.
 *
 * Source order matters. nginx proxies the login-ui block with
 * `X-Real-IP $remote_addr` (set) but `X-Forwarded-For $proxy_add_x_forwarded_for`
 * (appended), so the *leftmost* XFF entry is whatever the client sent and is
 * spoofable — a sprayer could mint a fresh bucket per request from it. X-Real-IP
 * is overwritten by nginx; the last XFF entry is the hop nginx appended. Both
 * are the real peer. The leftmost is never used.
 */
async function clientIP(): Promise<string | undefined> {
  let incoming: Awaited<ReturnType<typeof requestHeaders>>
  try {
    incoming = await requestHeaders()
  } catch {
    // outside a request scope — no end user to attribute this to
    return undefined
  }
  const forwarded = incoming.get("x-forwarded-for")?.split(",").pop()
  const candidate = (incoming.get("x-real-ip") || forwarded || "").trim()
  return IPV4.test(candidate) || IPV6.test(candidate) ? candidate : undefined
}

export type GoResult = { status: number; data: Record<string, unknown> }

export async function callLoginAPI(
  path: string,
  opts: { host: string; token?: string; body?: unknown },
): Promise<GoResult> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Login-UI-PAT": PAT,
    "X-Forwarded-Host": opts.host,
  }
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`

  const ip = await clientIP()
  if (ip) headers["X-Forwarded-For"] = ip

  const res = await fetch(`${GO_API}/api/v1/login${path}`, {
    method: "POST",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    cache: "no-store",
  })

  let data: Record<string, unknown> = {}
  try {
    data = (await res.json()) as Record<string, unknown>
  } catch {
    // empty or non-JSON body
  }
  return { status: res.status, data }
}

/**
 * silentComplete attempts the SSO fast-path finalize. Returns the provider
 * resume URL on success, or null when the auth request demands interaction
 * (prompt=login / unsatisfied max_age) or the session is invalid.
 */
export async function silentComplete(token: string, authRequest: string, host: string): Promise<string | null> {
  const { status, data } = await callLoginAPI("/complete", { host, token, body: { authRequest } })
  if (status === 200 && typeof data.redirectTo === "string") {
    return data.redirectTo
  }
  return null
}

export type SessionInfo = { active: true; email: string }

/**
 * resolveSession reports whether the session token is a live, fully
 * authenticated login session — the "already signed in" check for a standalone
 * visit (no auth request). Returns null when the session is absent, only
 * partially authenticated (just /check ran), or expired.
 */
export async function resolveSession(token: string, host: string): Promise<SessionInfo | null> {
  const { status, data } = await callLoginAPI("/session", { host, token })
  if (status === 200 && data.active === true) {
    return { active: true, email: typeof data.email === "string" ? data.email : "" }
  }
  return null
}
