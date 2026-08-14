/**
 * Browser-side WebAuthn (passkey) encoding helpers (add-webauthn-passkeys).
 *
 * The gateway speaks the go-webauthn JSON wire format, where every ArrayBuffer
 * field (challenge, credential ids, attestation/assertion bytes) is base64url
 * without padding. The browser `navigator.credentials` API instead wants/returns
 * real ArrayBuffers, so these helpers convert the creation/request options coming
 * IN and the attestation/assertion credential going OUT.
 *
 * This module runs in the client bundle (uses atob/btoa) — it holds no secrets.
 */

function b64urlToBuffer(value: string): ArrayBuffer {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4))
  const base64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/")
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

function bufferToB64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

type Descriptor = { id: string; type: string; transports?: string[] }

/** Converts the gateway's creation options (publicKey) into the shape
 *  navigator.credentials.create() expects (ArrayBuffer challenge/ids). */
export function toCreationOptions(publicKey: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const pk = publicKey as Record<string, unknown> & {
    challenge: string
    user: { id: string } & Record<string, unknown>
    excludeCredentials?: Descriptor[]
  }
  return {
    ...(pk as unknown as PublicKeyCredentialCreationOptions),
    challenge: b64urlToBuffer(pk.challenge),
    user: { ...pk.user, id: b64urlToBuffer(pk.user.id) } as PublicKeyCredentialUserEntity,
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({
      ...c,
      id: b64urlToBuffer(c.id),
    })) as PublicKeyCredentialDescriptor[],
  }
}

/** Converts the gateway's request options (publicKey) into the shape
 *  navigator.credentials.get() expects (ArrayBuffer challenge/ids). */
export function toRequestOptions(publicKey: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const pk = publicKey as Record<string, unknown> & {
    challenge: string
    allowCredentials?: Descriptor[]
  }
  return {
    ...(pk as unknown as PublicKeyCredentialRequestOptions),
    challenge: b64urlToBuffer(pk.challenge),
    allowCredentials: (pk.allowCredentials ?? []).map((c) => ({
      ...c,
      id: b64urlToBuffer(c.id),
    })) as PublicKeyCredentialDescriptor[],
  }
}

/** Serializes a PublicKeyCredential (from create() or get()) into the base64url
 *  JSON the go-webauthn parser expects. Registration responses carry
 *  attestationObject; assertion responses carry authenticatorData/signature. */
export function encodeCredential(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse
  const json: Record<string, unknown> = {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
  }
  if (credential.authenticatorAttachment) {
    json.authenticatorAttachment = credential.authenticatorAttachment
  }
  if (response.attestationObject) {
    json.response = {
      attestationObject: bufferToB64url(response.attestationObject),
      clientDataJSON: bufferToB64url(response.clientDataJSON),
    }
  } else {
    const out: Record<string, unknown> = {
      authenticatorData: bufferToB64url(response.authenticatorData),
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      signature: bufferToB64url(response.signature),
    }
    if (response.userHandle) out.userHandle = bufferToB64url(response.userHandle)
    json.response = out
  }
  return json
}
