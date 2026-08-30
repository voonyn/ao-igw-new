# 0005 - Audience-scoped resource servers

## Context

The gateway serves more than one API from one issuer. The admin management API
answers `console-ui`, and the self-service account API answers `portal-ui`. Both
accept the access tokens of the same tenant.

An access token with no `aud` names no API. Any resource server that verifies only
the signature and the issuer then accepts it. A token minted for the account API
reaches the admin API, and a person who can read their own profile can call an
administrative endpoint.

The tokens are JWTs, and each resource server verifies them locally. No store is
read, so `aud` is the only claim that separates one API from another.

## Decision

Every API of the gateway requires an audience.

A tenant declares its resource identifiers in one JSON column on
`oidc_provider_configs`. `bootstrap` seeds two: `urn:alphaomega:admin-api` and
`urn:alphaomega:account-api`. The provider of the tenant passes the list to
`WithResourceIndicators`, so `/authorize` accepts a `resource` parameter that names
one of them. See RFC 8707.

Both front ends send a `resource` value. `console-ui` sends the admin identifier,
and `portal-ui` sends the account identifier.

The indicator is enabled, and it is not required. The gateway does not call
`WithResourceIndicatorsRequired`.

The bearer middleware takes the identifier of the API it guards. It checks the
signature against the key set of the tenant, then `iss`, `exp`, and `aud`. A token
that names another resource is refused with 401.

## Alternatives

- **Require the indicator.** Every client must then send a `resource` value, and a
  client that omits one is refused at `/authorize`. It is the stronger rule, and it
  breaks a client the tenant registered before the column existed. A token with no
  `aud` is already refused at the resource server, so the weaker rule loses nothing
  and it breaks nothing.
- **Check a scope instead of the audience.** A scope says what a client may ask for.
  It does not name the API that answers. Two APIs of one issuer would need two
  disjoint scope sets, and a scope the tenant renames would change who can call what.
- **One resource server, one issuer.** It removes the problem by removing the case.
  It also means one gateway process per API, and each one needs its own keys, its own
  discovery document, and its own domain.

## Consequences

- A client that sends no `resource` receives a token with no `aud`. Every resource
  server refuses it. The client works until it calls an API, and then it fails with
  401. This is accepted, and the alternative above says why.
- A tenant that adds an API must add its identifier to the column. A token cannot
  name a resource the tenant did not declare.
- An access token stays valid until `exp`, even after a logout. It is a JWT that no
  store holds. A logout revokes the grant, so no new token is minted, and the one
  already issued lives out its lifetime. See `internal/api/oidc/logout.go`.
- The two identifiers are Go constants in `internal/oidc`. A front end repeats the
  string in its environment, and the two must agree.
- The audience is minted only when the policy grants the resource the engine
  validated. `internal/api/oidc/policy.go` sets `GrantedResources` beside
  `GrantedScopes`. goidc copies the granted set onto the grant, the grant onto the
  token, and the token onto the `aud` claim. An unset `GrantedResources` breaks the
  chain at the first link, and every token is then minted with no `aud`. Commit
  `f6a9abf` wired it.
- A broken chain has two symptoms, and the first is the one to expect. A client
  that sends `resource` only at `/authorize` receives a token with no `aud`, and
  the bearer middleware refuses it with 401. `portal-ui` and `console-ui` both send
  it that way. A client that also sends `resource` at `/token` is refused at the
  token endpoint with `invalid_target`, and the integration harness sends it that
  way. The commit message of `f6a9abf` names only the second symptom.
- The audience rule is proved end to end by `TestAccountAPIFlow`, which skips
  unless `integrationEnv=1`. A default `go test ./...` passes while the chain is
  broken.
