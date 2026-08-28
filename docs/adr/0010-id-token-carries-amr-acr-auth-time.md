# 0010 - The ID token carries amr, acr and auth_time

## Context

A Login Session records every Factor a person proved, with the moment they proved it.
Nothing published it. `IDTokenClaims` added `sid` and the Claim Mapper output, and no
more. `interaction()` read `AuthTime` for `prompt=login` and for `max_age`, then
discarded it.

The gateway already reserved the three names. A Claim Mapper cannot write `amr`,
`acr` or `auth_time`. The slot was held for the gateway and never filled.

Adding TOTP gave the claims a consumer. A relying party that accepts tokens from this
gateway had no way to tell a password-only sign-in from a two-factor one.

## Decision

The ID token carries `amr`, `acr` and `auth_time`.

`amr` holds the Factor names of the Login Session, and `mfa` as well when the person
proved two or more. A redeemed Recovery Code reports `otp`, because it is the
break-glass of that Factor.

`acr` names the Assurance Level. It is `1fa` for one Factor and `2fa` for two or
more. The prefix is configured: `oidc.acr_prefix`, bound to `AO_OIDC_ACR_PREFIX`,
defaulting to `urn:alphaomega:acr`. The gateway advertises both values in
`acr_values_supported`.

`auth_time` is the moment the person last proved a Factor. OpenID Connect requires it
when the request carries `max_age`.

The three claims describe one sign-in event. The values are written onto the Authn
Session store at authorization, and read back when a token is minted, so they never
change afterwards.

A requested `acr_values` never raises the bar of the sign-in. It is a voluntary hint,
and a client that needs two Factors reads `acr` back and decides for itself.

The two values are a closed set. An authorization request that names any other value
is refused with `invalid_request`. goidc feeds one list to both the discovery
document and that check, so advertising the pair and refusing a third value are one
decision, not two.

## Alternatives

- **Publish nothing** — the reserved names stay empty, and a relying party cannot
  tell one Factor from two. The reservation shows the intent, and TOTP gives it a
  consumer.
- **Read the Factors again when a token is minted** — a refresh would then report the
  Factors the person holds now. `amr` states what happened at one sign-in, not what
  is true today. The read also fails once the Login Session expires, while the Grant
  lives on.
- **Numeric assurance levels** — `0`, `1` and `2` name the ISO 29115 ladder. This
  gateway does not implement that ladder, and borrowing its numbers claims an
  assurance it does not measure.
- **Honour `acr_values` and force a Second Factor** — client-driven step-up. It needs
  a route back to the challenge from inside an authorization request, and it lets any
  client raise the bar for a tenant that did not ask for it. It is its own feature.
- **A second store writer for the array** — the store round-trips through JSON, so a
  `[]string` returns as `[]any`. One space-delimited string reuses `remember`
  unchanged, the way `scope` already encodes a list.
- **Strip an unknown `acr_values` before goidc validates it** — middleware on the hot
  path of every authorization request, to accept a value the gateway then ignores. It
  buys tolerance for a client that has not appeared.

## Consequences

- A refreshed ID token reports the Factors of the original sign-in. A person who
  removed TOTP still sees `otp` in `amr` until the Grant ends. This is deliberate.
- `amr` carries `vc` for a QR Login. The AMR registry lists no value for a Wallet
  presentation, and the registry permits a deployment to name its own.
- The two `acr` values are a published contract. Renaming one breaks every relying
  party that branches on it, so the prefix is set once per Deployment and never
  changed after clients arrive.
- `acr` says how many Factors, never which. A relying party that needs the names
  reads `amr`.
- A client that sends an `acr_values` outside the two published values receives
  `invalid_request` at `/authorize`. Nothing regressed. An empty list refused every
  value before these two were published.
