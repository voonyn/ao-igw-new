// Unit test for the account-health derivation. Node 24 strips types natively, so
// this runs with no test framework and no new dependency:
//
//   node --test src/lib/health.test.ts
//
// The import carries its explicit .ts extension and no `@/` alias — Node resolves
// it, and the alias would need a bundler this file deliberately does not use.

import assert from "node:assert/strict"
import { test } from "node:test"

import { deriveHealth, type HealthInputs } from "./health.ts"

// A fully-secured account: every input known, every check passing.
const SECURE: HealthInputs = {
  totpEnabled: true,
  passkeys: [{ id: "k1", name: "iPhone", createdAt: "2026-07-01T00:00:00Z", lastUsedAt: "" }],
  emailVerified: true,
  activity: [{ id: "e1", action: "login.succeeded", entityType: "user", result: "success", createdAt: "2026-07-24T00:00:00Z" }],
  sessionCount: 2,
}

function stateOf(h: ReturnType<typeof deriveHealth>, id: string) {
  const c = h.checks.find(function (x) { return x.id === id })
  assert.ok(c, `no check ${id}`)
  return c.state
}

test("all checks passing scores 100", function () {
  const h = deriveHealth(SECURE)
  assert.equal(h.score, 100)
  assert.equal(h.scored, 4)
  assert.equal(h.passing, 4)
  assert.equal(h.checks.filter(function (c) { return c.state !== "good" }).length, 0)
})

test("second factor passes on a passkey alone", function () {
  const h = deriveHealth({ ...SECURE, totpEnabled: false })
  assert.equal(stateOf(h, "2fa"), "good")
  assert.equal(stateOf(h, "passkey"), "good")
  assert.equal(h.score, 100)
})

test("second factor passes on TOTP alone", function () {
  const h = deriveHealth({ ...SECURE, passkeys: [] })
  assert.equal(stateOf(h, "2fa"), "good")
  // Passwordless is a separate check and genuinely fails with no passkey: 3 of 4.
  assert.equal(stateOf(h, "passkey"), "warn")
  assert.equal(h.score, 75)
})

test("second factor passes on TOTP even when passkeys are unavailable", function () {
  const h = deriveHealth({ ...SECURE, passkeys: null })
  assert.equal(stateOf(h, "2fa"), "good")
  assert.equal(stateOf(h, "passkey"), "unknown")
})

test("no second factor at all fails, and is listed for the user to fix", function () {
  const h = deriveHealth({ ...SECURE, totpEnabled: false, passkeys: [] })
  assert.equal(stateOf(h, "2fa"), "warn")
  assert.equal(h.score, 50)
  const failing = h.checks.filter(function (c) { return c.state === "warn" })
  assert.deepEqual(failing.map(function (c) { return c.nav }), ["security", "security"])
})

test("a failed sign-in in the page fails that check", function () {
  const h = deriveHealth({
    ...SECURE,
    activity: [{ id: "e1", action: "login.failed", entityType: "user", result: "failure", createdAt: "2026-07-24T00:00:00Z" }],
  })
  assert.equal(stateOf(h, "signins"), "warn")
  assert.equal(h.score, 75)
})

test("an unknown check leaves the score alone rather than depressing it", function () {
  // TOTP not mounted: 2fa still passes on the passkey, and the score is over the
  // three checks that could be answered — not four with one counted as a failure.
  const h = deriveHealth({ ...SECURE, totpEnabled: null })
  assert.equal(h.score, 100)
  assert.equal(h.scored, 4)

  // The check that actually goes unknown is excluded from both sides.
  const g = deriveHealth({ ...SECURE, activity: null })
  assert.equal(stateOf(g, "signins"), "unknown")
  assert.equal(g.scored, 3)
  assert.equal(g.passing, 3)
  assert.equal(g.score, 100)
})

test("an unknown check is never counted as passing", function () {
  const h = deriveHealth({ ...SECURE, totpEnabled: null, passkeys: null, activity: null, emailVerified: false })
  assert.equal(stateOf(h, "2fa"), "unknown")
  assert.equal(h.passing, 0)
  assert.equal(h.scored, 1)
  assert.equal(h.score, 0)
})

test("every input unknown does not divide by zero", function () {
  const h = deriveHealth({ totpEnabled: null, passkeys: null, emailVerified: null, activity: null, sessionCount: null })
  assert.equal(h.scored, 0)
  assert.equal(h.score, 0)
  assert.ok(Number.isFinite(h.score), "score must be a number, not NaN")
  assert.equal(h.checks.filter(function (c) { return c.state === "unknown" }).length, 4)
})

test("the session row is informational and never scored", function () {
  const h = deriveHealth({ ...SECURE, sessionCount: 9 })
  assert.deepEqual(h.sessions, { count: 9, known: true })
  assert.equal(h.scored, 4, "sessions must not enter the denominator")

  const unknown = deriveHealth({ ...SECURE, sessionCount: null })
  assert.equal(unknown.sessions.known, false)
  assert.equal(unknown.score, 100)
})
