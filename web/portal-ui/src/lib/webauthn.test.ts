// Unit test for the two Passkey message mappers. Node strips types itself, so
// this runs with no test framework and no new dependency:
//
//   node --experimental-strip-types --test src/lib/webauthn.test.ts
//
// Node 24 needs no flag. Drop it once the toolchain is on 24.
//
// The import carries its explicit .ts extension and no `@/` alias — Node resolves
// it, and the alias would need a bundler this file deliberately does not use.
//
// Only the mappers are tested. `createPasskey` and `passkeysSupported` call the
// browser, and a test of them would test a mock of the browser.

import assert from "node:assert/strict"
import { test } from "node:test"

import { browserPasskeyMessage, passkeyMessage } from "./webauthn.ts"

// domError builds what the browser throws: a DOMException carries the reason in
// its `name`, and every branch below reads that name and nothing else.
function domError(name: string): Error {
  const err = new Error(name)
  err.name = name
  return err
}

test("a cancelled prompt carries no message", function () {
  assert.equal(browserPasskeyMessage(domError("NotAllowedError")), "")
  assert.equal(browserPasskeyMessage(domError("AbortError")), "")
})

test("a device that already holds a passkey says so", function () {
  assert.match(browserPasskeyMessage(domError("InvalidStateError")), /already/i)
})

test("an unknown browser failure still reads as a sentence", function () {
  const message = browserPasskeyMessage(domError("SecurityError"))
  assert.notEqual(message, "")
  assert.match(message, /\.$/)
})

// Every slug the gateway answers on these routes gets a message of its own, and
// no two of them read the same. A slug that fell through to the generic message
// would tell a person to retry a thing that cannot succeed.
test("every gateway slug maps to a message of its own", function () {
  const slugs = [
    "passkey_origin_refused",
    "passkey_challenge_expired",
    "passkey_rejected",
    "passkey_unavailable",
    "passkey_limit_reached",
    "passkey_duplicate",
    "passkey_not_found",
    "invalid_credentials",
    "directory_unavailable",
    "directory_no_entry",
    "mfa_unavailable",
    "rate_limited",
    "invalid_input",
    "unauthorized",
  ]
  const seen = new Set<string>()
  for (const slug of slugs) {
    const message = passkeyMessage(400, slug)
    assert.notEqual(message, "", `no message for ${slug}`)
    assert.equal(seen.has(message), false, `${slug} repeats another message`)
    seen.add(message)
  }
})

// The slug is read before the status. `passkey_rejected` arrives as a 401 and
// does not mean the portal session ended, so a status-first branch would send a
// person to the sign-in screen over a device that did not answer.
test("a refused passkey is not read as a lost session", function () {
  assert.match(passkeyMessage(401, "passkey_rejected"), /device/i)
  assert.match(passkeyMessage(401, "unauthenticated"), /session/i)
})

// The wrong password on a removal arrives as a 401 too. A status-first branch
// would send a person to the sign-in screen over one mistyped password.
test("a wrong password is not read as a lost session", function () {
  assert.match(passkeyMessage(401, "invalid_credentials"), /password/i)
})

// A person their organization's directory owns re-proves the removal with a bind.
// A directory that did not answer is not a wrong password, and a message that
// said it was would send that person hunting for a password that is right.
test("a directory that did not answer is not read as a wrong password", function () {
  const message = passkeyMessage(503, "directory_unavailable")
  assert.match(message, /directory/i)
  assert.doesNotMatch(message, /incorrect/i)
})

// A person whom no single directory entry proves holds a broken account. Nothing
// they do makes the next try work, so the copy must send them to an administrator
// and never to the retry the outage copy offers.
test("a broken directory account is not told to try again", function () {
  const message = passkeyMessage(409, "directory_no_entry")
  assert.match(message, /administrator/i)
  assert.doesNotMatch(message, /try again/i)
})

test("a status with no slug still maps", function () {
  assert.match(passkeyMessage(429, undefined), /wait/i)
  assert.match(passkeyMessage(404, undefined), /not available/i)
  assert.match(passkeyMessage(500, undefined), /went wrong/i)
})
