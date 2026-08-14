"use server"

import { cookies, headers } from "next/headers"

import { callLoginAPI } from "@/lib/login-api"
import { SESSION_COOKIE, parseSessionCookie } from "@/lib/session-cookie"

// ScopeConsent mirrors the gateway's per-scope consent payload: the display
// metadata the screen renders for one requested scope.
export type ScopeConsent = {
  name: string
  displayName: string
  description: string
  claims: string[]
}

export type CompleteResult =
  | { ok: true; redirectTo: string }
  | { ok: true; consentRequired: true; client: { clientId: string }; scopes: ScopeConsent[] }
  | { ok: false; error: string }

// Server Action for the finalize step. Finalizes the auth request against the
// session; the gateway returns either the provider resume URL, or — for a
// non-first-party client without prior consent — a consent-required payload the
// client renders as the consent screen. The cookie already holds the latest
// token from the password step, so no rotation is needed here.
export async function completeLogin(authRequest: string): Promise<CompleteResult> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }
  if (!authRequest) {
    return { ok: false, error: "invalid_request" }
  }

  const host = (await headers()).get("host") ?? ""

  const { status, data } = await callLoginAPI("/complete", {
    host,
    token: cookie.token,
    body: { authRequest },
  })

  if (status === 200 && data.consentRequired === true) {
    return {
      ok: true,
      consentRequired: true,
      client: parseClient(data.client),
      scopes: parseScopes(data.scopes),
    }
  }
  if (status !== 200 || typeof data.redirectTo !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "complete_failed" }
  }

  return { ok: true, redirectTo: data.redirectTo }
}

// submitConsent records the user's decision on the consent screen and returns
// the URL to hand the browser: the provider resume URL (approve) or the client's
// error redirect (deny). Both arrive as {redirectTo}.
export async function submitConsent(
  authRequest: string,
  approved: boolean,
): Promise<{ ok: true; redirectTo: string } | { ok: false; error: string }> {
  const cookieStore = await cookies()
  const cookie = parseSessionCookie(cookieStore.get(SESSION_COOKIE)?.value)
  if (!cookie) {
    return { ok: false, error: "session_invalid" }
  }
  if (!authRequest) {
    return { ok: false, error: "invalid_request" }
  }

  const host = (await headers()).get("host") ?? ""
  const { status, data } = await callLoginAPI("/consent", {
    host,
    token: cookie.token,
    body: { authRequest, approved },
  })

  if (status !== 200 || typeof data.redirectTo !== "string") {
    return { ok: false, error: typeof data.error === "string" ? data.error : "consent_failed" }
  }
  return { ok: true, redirectTo: data.redirectTo }
}

function parseClient(raw: unknown): { clientId: string } {
  if (raw && typeof raw === "object" && typeof (raw as { clientId?: unknown }).clientId === "string") {
    return { clientId: (raw as { clientId: string }).clientId }
  }
  return { clientId: "" }
}

function parseScopes(raw: unknown): ScopeConsent[] {
  if (!Array.isArray(raw)) return []
  return raw.map((s) => {
    const o = (s ?? {}) as Record<string, unknown>
    return {
      name: typeof o.name === "string" ? o.name : "",
      displayName: typeof o.displayName === "string" ? o.displayName : "",
      description: typeof o.description === "string" ? o.description : "",
      claims: Array.isArray(o.claims) ? o.claims.filter((c): c is string => typeof c === "string") : [],
    }
  })
}
