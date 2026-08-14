// Maps the gateway's coarse account-recovery error codes to user-facing copy.
// Pure (no server imports) so client components can call it directly.
export function recoveryErrorMessage(code: string): string {
  switch (code) {
    case "invalid_token":
      return "This link is invalid or has expired. Please request a new one."
    case "weak_password":
      return "Please choose a stronger password (at least 8 characters)."
    case "invalid_credentials":
      return "Your current password is incorrect."
    case "session_invalid":
      return "Your session has expired. Please sign in again."
    default:
      return "Something went wrong. Please try again."
  }
}
