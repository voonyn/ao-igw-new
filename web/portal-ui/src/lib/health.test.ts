// Unit test for the account-health derivation. Node strips types itself, so this
// runs with no test framework and no new dependency:
//
//   node --experimental-strip-types --test src/lib/health.test.ts
//
// Node 24 needs no flag. Drop it once the toolchain is on 24.
//
// The import carries its explicit .ts extension and no `@/` alias — Node resolves
// it, and the alias would need a bundler this file deliberately does not use.

import assert from "node:assert/strict"
import { test } from "node:test"

import { deriveHealth, type HealthInputs } from "./health.ts"

// A healthy account: every input known, every check passing.
const SECURE: HealthInputs = {
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
  assert.equal(h.scored, 2)
  assert.equal(h.passing, 2)
  assert.equal(h.checks.filter(function (c) { return c.state !== "good" }).length, 0)
})

test("the checklist holds only the checks this deployment can serve", function () {
  const h = deriveHealth(SECURE)
  assert.deepEqual(h.checks.map(function (c) { return c.id }), ["email", "signins"])
})

test("an unverified email fails, and is listed for the user to fix", function () {
  const h = deriveHealth({ ...SECURE, emailVerified: false })
  assert.equal(stateOf(h, "email"), "warn")
  assert.equal(h.score, 50)
  const failing = h.checks.filter(function (c) { return c.state === "warn" })
  assert.deepEqual(failing.map(function (c) { return c.nav }), ["profile"])
})

test("a failed sign-in in the page fails that check", function () {
  const h = deriveHealth({
    ...SECURE,
    activity: [{ id: "e1", action: "login.failed", entityType: "user", result: "failure", createdAt: "2026-07-24T00:00:00Z" }],
  })
  assert.equal(stateOf(h, "signins"), "warn")
  assert.equal(h.score, 50)
})

test("an unknown check leaves the score alone rather than depressing it", function () {
  // The check that goes unknown is excluded from both sides of the score.
  const h = deriveHealth({ ...SECURE, activity: null })
  assert.equal(stateOf(h, "signins"), "unknown")
  assert.equal(h.scored, 1)
  assert.equal(h.passing, 1)
  assert.equal(h.score, 100)
})

test("an unknown check is never counted as passing", function () {
  const h = deriveHealth({ ...SECURE, activity: null, emailVerified: false })
  assert.equal(h.passing, 0)
  assert.equal(h.scored, 1)
  assert.equal(h.score, 0)
})

test("every input unknown does not divide by zero", function () {
  const h = deriveHealth({ emailVerified: null, activity: null, sessionCount: null })
  assert.equal(h.scored, 0)
  assert.equal(h.score, 0)
  assert.ok(Number.isFinite(h.score), "score must be a number, not NaN")
  assert.equal(h.checks.filter(function (c) { return c.state === "unknown" }).length, 2)
})

test("the session row is informational and never scored", function () {
  const h = deriveHealth({ ...SECURE, sessionCount: 9 })
  assert.deepEqual(h.sessions, { count: 9, known: true })
  assert.equal(h.scored, 2, "sessions must not enter the denominator")

  const unknown = deriveHealth({ ...SECURE, sessionCount: null })
  assert.equal(unknown.sessions.known, false)
  assert.equal(unknown.score, 100)
})
