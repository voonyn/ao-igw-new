// Unit test for the answer shape of the account proxy. Node strips types itself,
// so this runs with no test framework and no new dependency:
//
//   node --experimental-strip-types --test src/lib/server/account-proxy.test.ts
//
// Node 24 needs no flag. Drop it once the toolchain is on 24.
//
// The source is written for the Next bundler, which resolves a specifier with no
// extension. Node does not. One resolve hook supplies the two extensions the
// bundler adds — `.js` for `next/server`, `.ts` for a relative import — and it
// must run before the module loads, which is why the imports below are dynamic.

import assert from "node:assert/strict"
import * as nodeModule from "node:module"
import { test } from "node:test"

// Node 22 has the synchronous hook API. @types/node is on v20, which does not
// declare it yet, so the shape is named here.
type HookContext = { parentURL?: string }
type Next = (specifier: string, context: HookContext) => unknown
type Resolve = (specifier: string, context: HookContext, next: Next) => unknown
const { registerHooks } = nodeModule as unknown as { registerHooks: (hooks: { resolve: Resolve }) => void }

registerHooks({
  resolve(specifier, context, next) {
    if (specifier === "next/server") return next("next/server.js", context)
    // Only the source under test. `next` resolves its own relative requires,
    // and they are .js.
    const ours = context.parentURL?.includes("/src/lib/server/") ?? false
    if (ours && specifier.startsWith(".") && !/\.[a-z]+$/.test(specifier)) return next(`${specifier}.ts`, context)
    return next(specifier, context)
  },
})

// The seal key the cookie helper reads. Any 32 characters do: this test seals a
// session and opens it again in the same process.
process.env.AO_PORTAL_COOKIE_SECRET = "test-portal-cookie-secret-0123456789"

const { NextRequest } = await import("next/server.js")
const { PORTAL_SESSION_COOKIE, sealSession } = await import("./secure-cookie.ts")
const { forwardToAccountAPI } = await import("./account-proxy.ts")

// A live session, so the proxy uses the token as it stands and never refreshes.
async function request(): Promise<InstanceType<typeof NextRequest>> {
  const sealed = await sealSession({
    sub: "user-1",
    accessToken: "at-1",
    expiresAt: Date.now() + 60 * 60 * 1000,
  })
  return new NextRequest("http://localhost:3001/api/account/mfa/passkeys", {
    headers: { cookie: `${PORTAL_SESSION_COOKIE}=${sealed}` },
  })
}

// Answers one gateway reply, and restores the real fetch when the test ends.
function gatewayAnswers(status: number, body: unknown): () => void {
  const real = globalThis.fetch
  globalThis.fetch = async () =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })
  return () => {
    globalThis.fetch = real
  }
}

test("a 201 answers the data half, at 201", async (t) => {
  t.after(gatewayAnswers(201, { code: 201, status: "Created", message: "Created", data: { id: "p1", name: "Laptop" } }))

  const res = await forwardToAccountAPI(await request(), "/mfa/passkeys/register/finish", { method: "POST" })

  assert.equal(res.status, 201)
  assert.deepEqual(await res.json(), { id: "p1", name: "Laptop" })
})

test("a 200 answers the data half, at 200", async (t) => {
  t.after(gatewayAnswers(200, { code: 200, status: "OK", message: "OK", data: [{ id: "p1" }] }))

  const res = await forwardToAccountAPI(await request(), "/mfa/passkeys")

  assert.equal(res.status, 200)
  assert.deepEqual(await res.json(), [{ id: "p1" }])
})

test("an error passes the slug and the status through", async (t) => {
  t.after(gatewayAnswers(409, { code: 409, status: "Conflict", message: "already registered", error: "passkey_exists" }))

  const res = await forwardToAccountAPI(await request(), "/mfa/passkeys/register/finish", { method: "POST" })

  assert.equal(res.status, 409)
  assert.equal((await res.json()).error, "passkey_exists")
})
