/**
 * Server-side reads of the console's shared state.
 *
 * The client twin of this file is `loadConsoleData` in `@/lib/console-api`. It
 * reads the same five resources through the BFF route, from the browser. This
 * one reads them during the render, so the shell arrives with the HTML instead
 * of after a round trip the browser makes on mount.
 *
 * The access token comes from the sealed cookie. `proxy.ts` refreshed it before
 * this render and forwarded the refreshed cookie onto the request, so no refresh
 * happens here: a Server Component cannot write a cookie, and a rotation it
 * could not persist would lose the new refresh token.
 */

import { cookies } from "next/headers"

import { adminFetch } from "./admin-client"
import { unwrapJSON } from "./envelope"
import { CONSOLE_SESSION_COOKIE, openSession } from "./secure-cookie"
import type { CollectionKey, CollectionStatus, ConsoleData, Me, Outcome } from "@/lib/console-api"
import type { Bootstrap, Db, Key, ProviderConfig, Tenant } from "@/lib/types"

/** The access token of the caller, or null when the session is gone. */
async function accessToken(): Promise<string | null> {
  const jar = await cookies()
  const session = await openSession(jar.get(CONSOLE_SESSION_COOKIE)?.value)
  return session?.accessToken ?? null
}

/** A read that must answer. A non-200 throws, and the caller sends to login. */
async function get<T>(token: string, path: string): Promise<T> {
  const res = await adminFetch(token, path)
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`)
  return unwrapJSON<T>(await res.text())
}

/**
 * A read that may legitimately have no data, with the reason preserved. 403 and
 * 404 stay apart: an operator lacking a role needs a different sentence than a
 * subsystem that is not configured.
 */
async function getOptional<T>(token: string, path: string): Promise<Outcome<T>> {
  const res = await adminFetch(token, path)
  if (res.status === 403) return { ok: false, reason: "forbidden" }
  if (res.status === 404) return { ok: false, reason: "missing" }
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`)
  return { ok: true, data: unwrapJSON<T>(await res.text()) }
}

function outcome<T>(r: PromiseSettledResult<Outcome<T>>, fallback: T): [T, CollectionStatus] {
  if (r.status === "rejected") {
    return [fallback, { state: "error", message: r.reason instanceof Error ? r.reason.message : String(r.reason) }]
  }
  return r.value.ok ? [r.value.data, { state: "ok" }] : [fallback, { state: r.value.reason }]
}

/**
 * Loads who the caller is, which organizations they may read, and the bounded
 * singletons. It loads no list collection, for the same reason the client twin
 * does not: every growth-bearing read is paged and belongs to the view that
 * renders it.
 *
 * Returns null when the session is gone or `/me` refuses, and the layout then
 * sends the person to login.
 */
export async function loadConsoleData(): Promise<ConsoleData | null> {
  const token = await accessToken()
  if (!token) return null

  let me: Me
  try {
    me = await get<Me>(token, "/me")
  } catch {
    return null
  }

  const settled = await Promise.allSettled([
    getOptional<Key[]>(token, "/keys"),
    getOptional<ProviderConfig>(token, "/provider"),
    getOptional<Tenant>(token, "/tenant"),
    getOptional<Bootstrap>(token, "/bootstrap"),
  ] as const)

  const [keys, sKeys] = outcome(settled[0], [] as Key[])
  const [provider, sProvider] = outcome<ProviderConfig | null>(settled[1], null)
  const [resolved, sTenant] = outcome<Tenant | null>(settled[2], null)
  const [bootstrap, sBootstrap] = outcome<Bootstrap | null>(settled[3], null)

  const db: Db = {
    // The console is bound to one tenant. The multi-tenant list is SYSTEM scope
    // and deferred, so `tenants` holds only the resolved tenant.
    tenants: [resolved ?? me.tenant],
    keys,
    providerConfigs: provider ? { [me.tenant.id]: provider } : {},
  }

  const status: Record<CollectionKey, CollectionStatus> = {
    keys: sKeys,
    provider: sProvider,
    tenant: sTenant,
    bootstrap: sBootstrap,
  }
  return { me, db, bootstrap, status }
}

/**
 * One server-side read for a page that loads its own resource, such as the first
 * page of the audit feed. `path` is relative to `/api/v1/admin`.
 *
 * Returns null when the session is gone. A 403 and a 404 come back as outcomes,
 * so the view renders the sentence the reason deserves.
 */
export async function serverRead<T>(path: string): Promise<Outcome<T> | null> {
  const token = await accessToken()
  if (!token) return null
  try {
    return await getOptional<T>(token, path)
  } catch {
    return null
  }
}
