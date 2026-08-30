/**
 * Browser-side helpers for the login flow.
 *
 * Each step calls a Server Action (basePath-aware) that talks to the Go gateway
 * server-side; the session token and PAT never appear in the browser. This
 * module only maps backend error codes to user-facing copy.
 */

/**
 * stepFor maps the pending steps the gateway says are still owed to the route
 * that runs them. `webauthn` challenges a passkey holder, `otp` challenges an
 * enrolled user, and `webauthn_enroll` and `otp_enroll` force setup when policy
 * requires MFA. An empty set owes nothing, so the flow goes straight to the
 * finalize step.
 *
 * The gateway lists the steps most preferred first, and this reads them in the
 * same order. A person who holds both Second Factors lands on the passkey, and
 * that screen offers the other one as another method.
 *
 * Both enrolment steps route to the one screen. It offers a Passkey and an
 * Authenticator side by side, so a device with no authenticator never
 * dead-ends, and the person enrols one of the two.
 *
 * The names are compared whole. `webauthn_enroll` is not the `webauthn`
 * challenge, so a person who owes the enrolment is never sent to a challenge no
 * device of theirs can answer.
 *
 * These are steps, not factors. A factor is what the person already proved, and
 * it reaches the ID token as `amr`. Nothing here ever does. `otp` and `webauthn`
 * read the same in both places and mean the other thing: the challenge is owed,
 * not answered.
 *
 * Two steps read it. The password step routes forward on the answer it just
 * received, and the finalize step routes back on the same answer when the
 * gateway refuses a session that skipped one of these routes.
 */
export function stepFor(methods: string[]): string {
  if (methods.includes("webauthn")) return "/passkey"
  if (methods.includes("otp")) return "/verify"
  if (methods.includes("webauthn_enroll") || methods.includes("otp_enroll")) return "/enroll"
  return "/success"
}

/** messageForError maps a backend error code to user-facing copy. */
export function messageForError(code: unknown): string {
  switch (code) {
    case "invalid_credentials":
      return "Incorrect email or password."
    case "rate_limited":
      return "Too many attempts. Please wait a moment and try again."
    case "session_invalid":
      return "Your session expired. Please start again."
    case "reauthentication_required":
      return "Please sign in again to continue."
    case "insufficient_factors":
      return "Additional verification is required."
    default:
      return "Something went wrong. Please try again."
  }
}

/**
 * mfaMessageForError maps a backend error code to MFA-appropriate copy. The
 * gateway returns the generic `invalid_credentials` for a wrong TOTP or an
 * unknown/used recovery code, which reads wrong as "Incorrect email or password"
 * — so the code path gets its own phrasing.
 *
 * `too_many_codes` is the sign-in the gateway ended after too many wrong codes.
 * The session is dead, so the person is told to start again rather than to try
 * another code. `unauthenticated` is the same dead session reached one step
 * later, and it reads the same way here.
 */
export function mfaMessageForError(code: unknown): string {
  switch (code) {
    case "invalid_credentials":
      return "That code isn’t right. Please try again."
    case "too_many_codes":
      return "Too many incorrect codes. Please start again."
    case "rate_limited":
      return "Too many attempts. Please wait a moment and try again."
    case "unauthenticated":
    case "session_invalid":
      return "Your session expired. Please start again."
    default:
      return "Something went wrong. Please try again."
  }
}
