# 0012 - A passkey reports `webauthn` in amr

## Context

A Passkey joins TOTP as a Second Factor. [ADR 0010](0010-id-token-carries-amr-acr-auth-time.md)
publishes the Factor names of a Login Session in the `amr` claim. A relying party
branches on those names, so a name is a contract, and a rename breaks every client
that reads it.

The AMR registry of RFC 8176 lists two values that a WebAuthn assertion can plausibly
claim. `hwk` names proof of possession of a hardware-secured key. `swk` names proof of
possession of a software-secured key.

Neither value describes what this gateway knows. A Passkey moves between a secure
element and a software keystore, and the same person can sync one credential across
both. The gateway receives a signature and a public key. It receives no proof of where
the private half lives, unless it demands attestation and it maintains a metadata
list of authenticator models.

The registry permits a deployment to name a factor of its own. This gateway already
does that once: a scan reports `vc`.

## Decision

A Passkey reports `webauthn` in `amr`.

The Pending Step that asks for a passkey challenge carries the same text,
`webauthn`, and the enrolment step is `webauthn_enroll`. The step name and the Factor
name must match, because the finalize gate looks the step string up as a key in the
proved Factors of the Login Session. `otp` already works that way, and a step named
`passkey` beside a Factor named `webauthn` would be owed for ever.

The gate also demands every step it reads. A person who holds both Second Factors is
offered both, and proves one, so the gate must accept one proof for either challenge
step. A challenge step is therefore satisfied by any proved Second Factor. An
enrolment step keeps its exact match, because a person who owes enrolment has proved
nothing yet.

`acr` does not change. It counts Factors and never names them, so a sign-in with a
password and a Passkey reports the two-factor level, exactly as a password and a TOTP
code does today.

## Alternatives

- **Report `hwk`** — a registered value, and a false statement. The gateway cannot
  tell a hardware-bound credential from a synced one without attestation, so it would
  claim an assurance it never measured. A relying party that trusts `hwk` to mean a
  hardware key would be misled.
- **Report `swk`** — the same defect in the other direction. It understates a
  credential that a security key really did protect.
- **Report `hwk` or `swk` from the attestation** — it makes attestation mandatory,
  it needs a maintained metadata list of authenticator models, and a person on an
  authenticator that reports no attestation cannot register at all. It is its own
  feature, and no client has asked for it.
- **Report `mfa` alone** — `amr` already gains `mfa` when a person proved two or more
  Factors. It says that a second Factor happened, and never which one. A relying party
  that must refuse TOTP and accept a Passkey learns nothing from it.
- **Report `otp`** — it reuses the name a Recovery Code already reuses. A Passkey is
  not the break-glass of TOTP, and the two Factors have different strength. One name
  for both would hide that difference for ever.

## Consequences

- `webauthn` is a published contract from the first token that carries it. It is set
  once for this Deployment and never renamed.
- The value sits outside the RFC 8176 registry, beside `vc`. A relying party that
  matches the registry as a closed set does not recognise it. No such client exists
  today, and `acr` still answers the question most clients ask.
- A person who proved a Passkey and a password reports `["pwd","webauthn","mfa"]`. A
  person who proved a TOTP code reports `["pwd","otp","mfa"]`. A relying party can
  now tell the two Second Factors apart, which `acr` alone never allowed.
- The finalize gate changes. A challenge step now passes on any proved Second Factor,
  where it demanded an exact name before. Nothing regressed: the step list held one
  entry until now, so the two readings could not differ.
- A refreshed ID token reports the Factors of the original sign-in, exactly as
  [ADR 0010](0010-id-token-carries-amr-acr-auth-time.md) already decided. A person who
  removed the Passkey still sees `webauthn` until the Grant ends.
