// The browser half of the Passkey ceremonies, and the copy for every way one can
// fail. The sign-in runs two of them: the challenge a holder answers, and the
// registration a person the MFA Requirement governs runs instead.
//
// Nothing here reads inside the options or inside the answer. The options are
// what the device signs over, so a field this file picked out and rebuilt would
// change what the signature covers. The platform parses the one and serialises
// the other, and this file carries both across whole.

// passkeysSupported says whether this browser can run either ceremony.
//
// The check is the JSON helpers the code below calls, not `PublicKeyCredential`
// alone: a browser that has the credential API without them cannot take the
// options the gateway sends. Both helpers are demanded, and one answer covers
// both screens: a browser ships the pair together, and a screen that ran one
// ceremony but not the other would offer a passkey it cannot create.
//
// The control is disabled when this answers false, and it is never hidden — a
// person who sees no control cannot tell a missing feature from a broken page.
export function passkeysSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential === "function" &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function" &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function"
  )
}

// createPasskey asks the device to make one key pair and answers what the
// gateway stores.
//
// It is the enrolment twin of getPasskey, and it carries the options and the
// answer across whole for the same reason: every field of them is part of what
// the device signs.
export async function createPasskey(
  options: PublicKeyCredentialCreationOptionsJSON,
  signal: AbortSignal,
): Promise<PublicKeyCredentialJSON> {
  const credential = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
    signal,
  })
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("the browser answered no passkey")
  }
  return credential.toJSON()
}

// getPasskey asks the device to sign one challenge and answers what the gateway
// verifies.
//
// The signal aborts the pending prompt, so a person who switches to the
// Authenticator is not left with a browser sheet over a screen that moved on.
//
// It throws what the browser throws. `browserPasskeyMessage` reads the failure,
// because the caller renders it and this function does not own copy.
export async function getPasskey(
  options: PublicKeyCredentialRequestOptionsJSON,
  signal: AbortSignal,
): Promise<PublicKeyCredentialJSON> {
  const credential = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
    signal,
  })
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("the browser answered no passkey")
  }
  return credential.toJSON()
}

// browserPasskeyMessage says why the browser refused, and answers "" when the
// person cancelled.
//
// A cancel is a choice and not a failure, so the screen shows nothing and is
// usable again at once. `AbortError` is the same event from the other side: the
// screen itself called abort.
export function browserPasskeyMessage(err: unknown): string {
  const name = err instanceof Error ? err.name : ""
  if (name === "NotAllowedError" || name === "AbortError") return ""
  return "Your device could not answer. Please try again, or use another method."
}

// passkeyMessage says why the gateway refused one of the ceremony calls. The
// challenge and the enrolment share it, so a person reads one wording for a
// refusal that means one thing.
//
// The slug is read before the status, and never the message: the gateway carries
// the reason in the slug, so a reworded message never changes what a person
// reads here. `passkey_rejected` arrives as a 401 and does not mean the sign-in
// ended, which is why the two 401 branches are apart.
export function passkeyMessage(code: unknown): string {
  switch (code) {
    case "passkey_origin_refused":
      return "Passkeys are not set up for this web address. Please tell your administrator."
    case "passkey_challenge_expired":
      return "That took too long. Please try again."
    case "passkey_rejected":
      return "Your device could not be verified. Please try again."
    case "passkey_unknown_credential":
      return "That device is not registered on this account. Please use one of your own."
    case "passkey_unavailable":
      return "Passkeys are unavailable right now. Please try again in a moment."
    case "mfa_unavailable":
      return "Two-step verification is unavailable right now. Please try again in a moment."
    // The passkey was revoked while the prompt was open, so the write-back found
    // no row. The person answers with another method, or with another device.
    case "passkey_not_found":
      return "That passkey is no longer registered. Please use another method."
    case "no_passkey":
      return "There is no passkey on this account. Please use another method."
    // The account already holds a second factor, so this screen offered a step
    // it must not have. The person answers the challenge they owe, which the
    // password step names, so the only way on is to start again.
    case "mfa_already_held":
      return "Two-step verification is already set up on this account. Please start again."
    // The enrolment refusals. A device that already holds a passkey for this
    // account, and an account that holds the most passkeys allowed, both name a
    // state the person can act on.
    case "passkey_duplicate":
      return "This device already has a passkey for your account. Please use another method."
    case "passkey_limit_reached":
      return "Your account has the most passkeys allowed. Please use another method."
    case "rate_limited":
      return "Too many attempts. Please wait a moment and try again."
    case "unauthenticated":
    case "session_invalid":
      return "Your session expired. Please start again."
    default:
      return "Something went wrong. Please try again."
  }
}
