// The copy for the refusals of the password re-proof step.
//
// A person re-proves with the current password before the portal removes a
// passkey, removes a Second Factor, or replaces the recovery codes. The gateway
// answers the same three slugs to all of those: a wrong password, a directory
// that did not answer, and an account no single directory entry proves. The
// passkey screen and the manage screen once each held their own copy of the
// three lines, and a copy that drifted would show one wording on one screen and
// another wording on the other for one refusal.
//
// A screen that proves the person some other way does not belong here, even for
// the same slug. `activateMessage` in `mfa-enroll-modal.tsx` answers
// `invalid_credentials` for a wrong authenticator code, and the copy there must
// name the code and never the password.
//
// `invalid_input` does not belong here either: the passkey screen names no
// field, and the manage screen names the password, because each one caps a
// different set of fields in the browser.
const MESSAGES: Record<string, string> = {
  // The wrong password. It arrives as a 401 and does not mean the portal session
  // ended, so every caller reads the slug before the status.
  invalid_credentials: "Current password is incorrect.",
  // A person their organization's directory owns re-proves with a bind, so a
  // directory that did not answer refuses the change. It is never a wrong
  // password, and it must not read as one.
  federation_unavailable: "Your organization's directory did not respond. Please try again in a moment.",
  // No single directory entry proves the person. The state stays until somebody
  // edits the directory, so the copy never asks them to try again.
  federation_no_account: "Your account is not linked to a single directory entry. Please tell your administrator.",
}

// accountMessage answers the shared copy for a slug, and "" when the slug is not
// one this module owns.
//
// A caller reads its own slugs first, falls through to this map, and reads the
// status last. The empty answer is what tells it to keep going.
//
// The slug arrives in a gateway body, so the read is an own-property read:
// plain indexing would answer a function for `constructor` or `toString`, and
// the caller would render it.
export function accountMessage(code: unknown): string {
  return typeof code === "string" && Object.hasOwn(MESSAGES, code) ? MESSAGES[code] : ""
}
