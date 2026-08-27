# 0004 - Login by redirect and resume, with a blind authentication policy

## Context

`go-oidc` runs an authentication policy inside the `/authorize` request. The policy
must produce a subject. The gateway authenticates people in `login-ui`, a separate
Next.js application with its own session cookie, its own forms, and its own rules for
identifier lookup, passwords, and later factors.

The policy therefore has to reach a decision that another application owns.

## Decision

The policy is blind. It never reads a login session and it never verifies a
credential.

1. `/authorize` arrives. The policy redirects the browser to `login-ui` with the
   authn session id, and suspends the flow.
2. `login-ui` drives the person through identifier, then password, then consent.
3. `login-ui` calls the gateway to complete the flow. That call sets the subject and
   the granted scopes on the authn session.
4. The browser follows the resume URL back to `/authorize/{id}`. The policy sees a
   subject and succeeds.

`login-ui` is the single reader of the login session. When a live login session
already exists, `login-ui` completes the flow at once and the person sees only a
redirect.

`prompt=none` follows the same path. `login-ui` renders nothing, and it either
completes the flow or writes a `login_required` marker onto the authn session for the
policy to fail with.

The granted scopes are written once, at completion, from the recorded consent. No
later step widens them.

## Alternatives

- **The policy reads the login session cookie directly.** It removes one redirect from
  an already-authenticated request. It also puts the cookie rules, the session
  service, and the factor logic inside a callback owned by the library, and it splits
  the answer to "is this person logged in" across two places.
- **The policy renders the login form itself.** The library supports it. It would move
  the login experience out of Next.js and into Go templates.
- **Drop `prompt=none`.** Rejected, because a relying party needs a silent refresh in a
  hidden iframe.

## Consequences

- An already-authenticated request pays one extra redirect pair. This is accepted.
- On `prompt=none`, `login-ui` must never render a page. The request runs in a hidden
  iframe, so a rendered page is invisible and the flow hangs.
- The credential-verified state between the identifier step and completion lives in
  the login session, not in the authn session. The account pages and the OIDC flow
  then read one login state.
- Consent must be recorded before completion, because completion is the only writer of
  the granted scopes.
