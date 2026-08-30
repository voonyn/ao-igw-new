// The browser half of the Passkey registration ceremony, and the copy for every
// way it can fail.
//
// Nothing here reads inside the options or inside the answer. The options are
// what the device signs over, so a field this file picked out and rebuilt would
// change what the signature covers. The platform parses the one and serialises
// the other, and this file carries both across whole.

// passkeysSupported says whether this browser can run the ceremony at all.
//
// The check is the JSON pair the code below calls, not `PublicKeyCredential`
// alone: a browser that has the credential API without the JSON helpers cannot
// take the options the gateway sends. The control is disabled when this answers
// false, and it is never hidden — a person who sees no control cannot tell a
// missing feature from a broken page.
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" &&
    typeof window.PublicKeyCredential === "function" &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function"
}

// createPasskey asks the device to create one key pair and answers what the
// gateway verifies.
//
// The signal aborts the pending prompt, so a person who closes the dialog is not
// left with a browser sheet over a screen that moved on.
//
// It throws what the browser throws. `browserPasskeyMessage` reads the failure,
// because the caller renders it and this function does not own copy.
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

// browserPasskeyMessage says why the browser refused, and answers "" when the
// person cancelled.
//
// A cancel is a choice and not a failure, so the screen shows nothing and is
// usable again at once. `AbortError` is the same event from the other side: the
// screen itself called abort.
//
// `InvalidStateError` is the exclude list doing its work. The device already
// holds a Passkey for this account, and a second one would prove nothing more.
export function browserPasskeyMessage(err: unknown): string {
  const name = err instanceof Error ? err.name : ""
  if (name === "NotAllowedError" || name === "AbortError") return ""
  if (name === "InvalidStateError") return "This device already has a passkey for your account."
  return "Your device could not create a passkey. Please try again."
}

// passkeyMessage says why the gateway refused one of the three Passkey calls.
//
// The slug is read before the status, and never the message: the gateway carries
// the reason in the slug, so a reworded message never changes what a person
// reads here. `passkey_rejected` arrives as a 401 and does not mean the portal
// session ended, which is why the two 401 branches are apart.
export function passkeyMessage(status: number, code: unknown): string {
  if (code === "passkey_origin_refused") {
    return "Passkeys are not set up for this web address. Please tell your administrator."
  }
  if (code === "passkey_challenge_expired") return "That took too long. Please try again."
  if (code === "passkey_rejected") return "Your device could not be verified. Please try again."
  if (code === "passkey_unavailable") return "Passkeys are unavailable right now. Please try again in a moment."
  if (code === "mfa_unavailable") return "Two-step verification is unavailable right now. Please try again in a moment."
  if (code === "invalid_input") return "That name is too long. Use 255 characters or fewer."
  if (code === "rate_limited" || status === 429) return "Too many attempts. Please wait a minute and try again."
  // Both 401 slugs mean the same thing to a person: `unauthenticated` is the BFF
  // holding no token, and `unauthorized` is the gateway refusing the one it sent.
  if (code === "unauthenticated" || code === "unauthorized" || status === 401) {
    return "Your session is no longer valid. Sign in again."
  }
  if (status === 404) return "Passkeys are not available on this account."
  return "Something went wrong. Please try again."
}
