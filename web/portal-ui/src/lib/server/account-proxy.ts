import { NextRequest, NextResponse } from "next/server"

import { getOidcConfig } from "./oidc-config"
import { cookieOptions, openSession, PORTAL_SESSION_COOKIE, sealSession, type SessionTokens } from "./secure-cookie"
import { resolveAccessToken } from "./token"

// forwardToAccountAPI calls one address of the gateway account API with the
// caller's access token, and hands the answer back to the browser.
//
// The token is read server-side (keyed by the sealed cookie; the browser never
// sees it). Every route under /api/account/mfa does the same three things —
// resolve the token, forward the call, re-seal a rotated session — so they do it
// here once instead of once each.
//
// Every successful status answers the gateway envelope's `data` half, at the
// gateway's own status: the passkey registration finish answers 201, and the
// browser reads the row at 201. Every other status passes the gateway's slug
// and status straight through, so the view branches on the slug and never on a
// message.
//
// The gateway has no route that answers 204 — `response.NoContent` writes 200
// with a null `data`. A route that answered a real 204 would need its own
// branch here, because a body on a null-body status is a response the platform
// refuses to build.
//
// The portal session cookie is SameSite=Lax, so a cross-site POST cannot carry
// it — these routes are CSRF-safe without a separate token.
//
// `origin` names the origin the gateway must treat this call as coming from.
// The call is server to server, so no browser `Origin` reaches here, and a
// route that needs the gateway to check one names it. Only the passkey
// registration start does: it is the one call the gateway must refuse before a
// device creates a key pair.
export async function forwardToAccountAPI(
  req: NextRequest,
  path: string,
  init?: { method?: string; body?: unknown; origin?: string },
): Promise<NextResponse> {
  const session = await openSession(req.cookies.get(PORTAL_SESSION_COOKIE)?.value)
  const { accessToken, session: next, rotated } = await resolveAccessToken(session)
  if (!accessToken) {
    // No usable token server-side — the UI treats this as "sign in again".
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
  }

  const url = new URL(`/api/v1/account${path}`, getOidcConfig().issuer).toString()
  try {
    const res = await fetch(url, {
      method: init?.method ?? "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
        ...(init?.body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(init?.origin === undefined ? {} : { Origin: init.origin }),
      },
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
      cache: "no-store",
    })

    if (res.ok) {
      // The gateway answers this deployment's one envelope,
      // `{code, status, message, data}`. Anything else on the wire is a shape
      // the view cannot render, so it degrades to an empty object.
      const body = await res.json().catch(() => null)
      return await withRotation(NextResponse.json(body?.data ?? {}, { status: res.status }), rotated, next)
    }
    const data = await res.json().catch(() => ({ error: "server_error" }))
    return await withRotation(NextResponse.json(data, { status: res.status }), rotated, next)
  } catch (err) {
    console.error(`portal: account proxy failed for ${path}`, err)
    return await withRotation(NextResponse.json({ error: "upstream" }, { status: 502 }), rotated, next)
  }
}

// Re-seals a rotated session onto the response so a refresh triggered here isn't
// lost (the refresh_token may have rotated at the gateway).
async function withRotation(res: NextResponse, rotated: boolean, next: SessionTokens | null): Promise<NextResponse> {
  if (rotated && next) res.cookies.set(PORTAL_SESSION_COOKIE, await sealSession(next), cookieOptions)
  return res
}
