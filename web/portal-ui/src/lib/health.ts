// Account-health derivation shared by the Home dashboard and the Security view.
//
// Pure by design: it takes data the caller has already fetched and returns the
// checklist plus the score. No I/O, no React. Home and Security need the same
// answer from different fetch lifecycles, and a shared function serves both
// without either owning the other's loading — which is how the hardcoded `82`
// outlived every other fixture around it.
//
// Every input is nullable and null means "we could not find out": the endpoint
// failed. A check resting on an unknown input is itself `unknown` and is excluded
// from BOTH sides of the score, so an endpoint this deployment cannot answer
// cannot depress a score the user has no way to raise — and is never silently
// counted as passing either.
//
// The checks are only the ones this deployment can serve, and each one must be a
// row the user can act on. Passkey enrolment has no self-service API here, so no
// check rests on it. Two-step verification has one, and no check rests on it
// either: this function takes only what Home and Security both already fetch,
// and Home reads no second-factor state.

import type { AccountHealth, ActivityEventWire, HealthCheck } from "./types"

export interface HealthInputs {
  /** The `email_verified` claim; null when the OP asserted nothing either way. */
  emailVerified: boolean | null
  /** One page of the caller's audit feed; null when /activity failed. */
  activity: ActivityEventWire[] | null
  /** Active-session count; null when /sessions failed. */
  sessionCount: number | null
}

/** A check outcome: pass, fail, or "could not find out". */
type Tri = boolean | null

function row(id: string, label: string, nav: string, pass: Tri, detail: string, unknownDetail: string): HealthCheck {
  if (pass === null) return { id, label, nav, state: "unknown", detail: unknownDetail }
  return { id, label, nav, state: pass ? "good" : "warn", detail }
}

// The checklist states counts, and a stray plural reads as a bug in the data.
function plural(n: number, one: string, many: string): string {
  return n + " " + (n === 1 ? one : many)
}

export function deriveHealth(i: HealthInputs): AccountHealth {
  const failed = i.activity === null
    ? null
    : i.activity.filter(function (e) { return e.action === "login.failed" }).length

  const checks: HealthCheck[] = [
    row("email", "Email verified", "profile", i.emailVerified,
      i.emailVerified ? "Your sign-in email is verified" : "Verify it so account recovery reaches you",
      "Couldn’t check your email"),
    row("signins", "No failed sign-in attempts", "activity", failed === null ? null : failed === 0,
      failed ? plural(failed, "failed attempt", "failed attempts") + " in your recent activity" : "Nothing suspicious in your recent activity",
      "Couldn’t check your recent sign-ins"),
  ]

  const scored = checks.filter(function (c) { return c.state !== "unknown" }).length
  const passing = checks.filter(function (c) { return c.state === "good" }).length
  // Nothing scoreable → no score to state. Guarding the divide is the whole point:
  // an all-unknown account must read 0 with "couldn't check", never NaN.
  const score = scored === 0 ? 0 : Math.round((100 * passing) / scored)

  return {
    checks,
    score,
    passing,
    scored,
    sessions: { count: i.sessionCount ?? 0, known: i.sessionCount !== null },
  }
}
