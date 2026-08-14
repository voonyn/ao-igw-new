import { NextRequest, NextResponse } from "next/server"

import { adminFetch, adminMutate, resolveAccessToken } from "@/lib/server/admin-client"
import { cookieOptions, CONSOLE_SESSION_COOKIE, openSession, sealSession, type SessionTokens } from "@/lib/server/secure-cookie"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

type Ctx = { params: Promise<{ path: string[] }> }

// The console BFF. Opens the sealed session cookie, resolves a valid access token
// server-side (refreshing + re-sealing the cookie if it rotated — this route is
// excluded from the middleware, so it persists its own refresh), and proxies to
// the gateway `/api/v1/admin/*`. The browser never sees the token; it only ever
// talks to this same-origin endpoint. GET is read-only; POST/PATCH/DELETE are the
// write surface (the gateway enforces the IAM_OWNER gate — the BFF just forwards).

export async function GET(req: NextRequest, ctx: Ctx) {
  const { accessToken, session, rotated } = await resolveAccessToken(await openSessionFrom(req))
  if (!accessToken) return unauthenticated()

  const segments = await segmentsOf(ctx)
  const upstream = await adminFetch(accessToken, `/${segments}${req.nextUrl.search}`)
  return relay(upstream, rotated ? session : null)
}

export async function POST(req: NextRequest, ctx: Ctx) {
  return proxyMutation(req, ctx, "POST")
}

export async function PUT(req: NextRequest, ctx: Ctx) {
  return proxyMutation(req, ctx, "PUT")
}

export async function PATCH(req: NextRequest, ctx: Ctx) {
  return proxyMutation(req, ctx, "PATCH")
}

export async function DELETE(req: NextRequest, ctx: Ctx) {
  return proxyMutation(req, ctx, "DELETE")
}

async function proxyMutation(req: NextRequest, ctx: Ctx, method: "POST" | "PUT" | "PATCH" | "DELETE") {
  const { accessToken, session, rotated } = await resolveAccessToken(await openSessionFrom(req))
  if (!accessToken) return unauthenticated()

  const segments = await segmentsOf(ctx)
  const body = method === "DELETE" ? null : await req.text()
  const upstream = await adminMutate(accessToken, `/${segments}${req.nextUrl.search}`, method, body && body.length > 0 ? body : null)
  return relay(upstream, rotated ? session : null)
}

async function openSessionFrom(req: NextRequest): Promise<SessionTokens | null> {
  return openSession(req.cookies.get(CONSOLE_SESSION_COOKIE)?.value)
}

async function segmentsOf(ctx: Ctx): Promise<string> {
  const { path } = await ctx.params
  return (path ?? []).map(encodeURIComponent).join("/")
}

function unauthenticated() {
  return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
}

// Relays the upstream response and, when the token was refreshed, re-seals the
// rotated session onto the cookie so the new refresh_token isn't lost.
async function relay(upstream: Response, rotated: SessionTokens | null) {
  const body = await upstream.text()
  const res = new NextResponse(body, {
    status: upstream.status,
    headers: { "Content-Type": upstream.headers.get("Content-Type") ?? "application/json" },
  })
  if (rotated) res.cookies.set(CONSOLE_SESSION_COOKIE, await sealSession(rotated), cookieOptions)
  return res
}
