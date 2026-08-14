// Minimal browser-WebAuthn bridging for the passkey enrolment ceremony
// (wire-portal-passkeys 5.2). WebAuthn options carry ArrayBuffer fields, but they
// travel as base64url strings on the wire (the go-webauthn server encoding). These
// helpers convert between the two — no new dependency.

// b64urlToBuf decodes a base64url string to an ArrayBuffer.
export function b64urlToBuf(value: string): ArrayBuffer {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4))
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + pad
  const bin = atob(base64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes.buffer
}

// bufToB64url encodes an ArrayBuffer (or view) as an unpadded base64url string.
export function bufToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// Shape of the server's creation options (go-webauthn's CredentialCreation), with
// the base64url fields still as strings.
type ServerCreationOptions = {
  publicKey: {
    challenge: string
    user: { id: string; name: string; displayName: string }
    excludeCredentials?: { id: string; type: string; transports?: string[] }[]
    [k: string]: unknown
  }
}

// toCreationOptions turns the server's JSON creation options into the
// PublicKeyCredentialCreationOptions that navigator.credentials.create() expects,
// decoding the base64url challenge / user id / excluded credential ids to buffers.
export function toCreationOptions(opts: ServerCreationOptions): PublicKeyCredentialCreationOptions {
  const pk = opts.publicKey
  return {
    ...pk,
    challenge: b64urlToBuf(pk.challenge),
    user: { ...pk.user, id: b64urlToBuf(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({
      ...c,
      id: b64urlToBuf(c.id),
      type: c.type as PublicKeyCredentialType,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
  } as PublicKeyCredentialCreationOptions
}

// attestationToJSON serializes the created credential into the attestation JSON the
// gateway's finish endpoint parses (base64url rawId + response fields).
export function attestationToJSON(cred: PublicKeyCredential): string {
  const res = cred.response as AuthenticatorAttestationResponse
  return JSON.stringify({
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(res.clientDataJSON),
      attestationObject: bufToB64url(res.attestationObject),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  })
}
