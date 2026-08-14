/**
 * Browser-side helpers for the login flow.
 *
 * Each step calls a Server Action (basePath-aware) that talks to the Go gateway
 * server-side; the session token and PAT never appear in the browser. This
 * module only maps backend error codes to user-facing copy.
 */

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
 */
export function mfaMessageForError(code: unknown): string {
  switch (code) {
    case "invalid_credentials":
      return "That code isn’t right. Please try again."
    case "rate_limited":
      return "Too many attempts. Please wait a moment and try again."
    case "session_invalid":
      return "Your session expired. Please start again."
    default:
      return "Something went wrong. Please try again."
  }
}
