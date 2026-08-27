# 0003 - go-oidc as the protocol engine, one provider per tenant

## Context

The gateway must speak OpenID Connect and OAuth 2.0 to third-party clients. The
protocol is large, the security rules are subtle, and a mistake in them is a breach
rather than a bug.

Each tenant is its own OpenID Provider. A tenant owns its issuer, its signing keys,
its advertised scopes, and its token lifetimes. Two tenants share no protocol state.

`github.com/luikyv/go-oidc` builds on `net/http`. The gateway runs on Fiber v3.

## Decision

`go-oidc` v0.25.0 owns the protocol. The gateway owns identity, storage, and policy.

The gateway builds **one provider object per tenant**, not one provider for the whole
process. A request resolves to a tenant by its hostname. A registry then returns that
tenant's provider, building it on the first request and caching it for five minutes.

The provider is a `net/http` handler, bridged into Fiber with
`adaptor.HTTPHandler`. Protocol endpoints sit under `/oidc/v1`. Discovery stays at
`/.well-known/openid-configuration`, because the specification puts it there.

Only `internal/api/oidc` imports the library. `internal/oidc` holds the domain and
knows nothing about it.

Grants and authn sessions persist as an encrypted blob plus a few extracted lookup
columns. They are not mapped to a column per field.

## Alternatives

- **Write the protocol by hand.** The old implementation proved the cost. PKCE,
  refresh rotation, introspection, and discovery are each a specification to read and
  a set of edge cases to get right.
- **One provider for the process, with the tenant passed through context.** The issuer,
  the signing keys, and the advertised scopes all differ per tenant, and every one of
  them is fixed when the provider is built. A single provider cannot vary them.
- **A column per field for grants and sessions.** The library's session type has more
  than twenty fields, several of them maps, and it gains fields between versions. A
  blob survives a library upgrade. A column layout does not.
- **`zitadel/oidc` or a hosted provider.** Both were rejected earlier, because the
  gateway is the product and the provider cannot be somebody else's service.

## Consequences

- A tenant configuration change goes live within five minutes on every instance.
  Signing keys, clients, and consent are read per request and are not delayed.
- A library upgrade is one isolated commit, because one package imports it.
- Client lookup travels through the library's dynamic registration interface, because
  the library offers no other way to load a client. Registration itself is refused.
- Refresh token reuse detection is the gateway's own work. The library rotates tokens
  but does not detect a replay.
