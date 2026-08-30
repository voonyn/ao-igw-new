# Identity Gateway

The identity gateway is a multi-tenant OpenID Provider. It authenticates people and
issues tokens to applications on behalf of a tenant.

## Language

### Tenancy

**Tenant**:
An isolated customer of the gateway. A tenant owns its own users, applications,
signing keys, and provider configuration.
_Avoid_: Account, workspace, realm, instance

**Deployment**:
One installation of the gateway, holding every tenant it serves. It owns what is
configured outside the database: the `AO_NOTIFICATION_*` defaults, and the
one-time `bootstrap`.
_Avoid_: Instance, installation, environment

**Instance**:
One running process of the gateway. A deployment runs several, and any one of
them serves any request. Use the word for nothing else.

**Organization**:
A group of people and projects inside one tenant. It is the unit a tenant
delegates administration to, and the unit a person self-registers into.
_Avoid_: Team, group, department, company

**Tenant Domain**:
A hostname that belongs to one tenant. The hostname on a request decides which
tenant serves it.
_Avoid_: Host, custom domain, vanity URL

**Provider Config**:
The protocol settings of one tenant: its issuer, its token lifetimes, and its
flow rules.
_Avoid_: Settings, OP config, realm config

**Issuer**:
The base URL that identifies one tenant as an OpenID Provider. It appears in every
token that tenant signs.
_Avoid_: Base URL, authority, OP URL

**Membership**:
The row that puts one person in one tenant or in one organization. It carries the
roles that person holds there. A person with no membership belongs to no
organization, which is normal.
_Avoid_: Assignment, enrollment, seat, association

**Role**:
A name on a membership that says what a person administers. The gateway declares
four: `IAM_OWNER` and `IAM_ADMIN` on a tenant, `ORG_OWNER` and `ORG_USER_MANAGER`
in an organization. A role is not a scope. A scope says what a client may ask for,
and a role says what a person may administer. No roles table exists, and the four
names are Go constants.
_Avoid_: Permission, privilege, group, scope

### Relying parties

**Project**:
A named group of applications inside one organization. It is how a tenant keeps
the applications of one product together. A project holds no protocol settings of
its own.
_Avoid_: Workspace, product, suite, folder

**Application**:
A product registered in a tenant. It is the thing a tenant administrator names and
manages in the console.
_Avoid_: App, service, integration

**Client**:
The protocol identity of an application: a client id, a redirect URI list, and an
authentication method. One application has one client.
_Avoid_: Relying party, RP, consumer, SPA

**First-Party Client**:
A client the tenant owns itself. A first-party client never asks the user for
consent, because the user already trusts the tenant.
_Avoid_: Internal client, trusted client, own app

### Authentication

**Subject**:
The stable identifier of the person a token describes. It is not an email address
and it is not a username.
_Avoid_: User id in protocol text, principal, sub

**Login Session**:
Proof that a person authenticated with this tenant, held across applications. It
lives longer than any single authorization request, and ending it signs the person
out of every application.
_Avoid_: Session, SSO session, browser session, cookie

**Authn Session**:
One authorization request in flight, from the moment the client arrives until the
gateway answers. It is short lived and it belongs to one client.
_Avoid_: Auth session, request session, transaction, flow state

**Factor**:
One thing a person proved during a Login Session, recorded with the moment they
proved it. The ID token carries the names in `amr`.
_Avoid_: Method, credential, step (see Pending Step), AMR

Note: a factor name is a value of the AMR registry of RFC 8176 where one fits. A
password is `pwd`, and an Authenticator code is `otp`. Where the registry lists no
value, this deployment names the factor itself, and the registry permits that. A
scan is `vc`, and a Passkey is `webauthn`.

The registry lists `hwk` and `swk`, and this deployment uses neither. Both name
where the private key lives, and a Passkey moves between a secure element and a
software keystore. The gateway cannot tell the two apart, so it claims neither.
See `docs/adr/0012-passkey-amr-value.md`.

**Second Factor**:
A Factor a person proves after the password. This deployment serves two: a TOTP
Enrolment, and a Passkey.
_Avoid_: 2FA, MFA, two-step, second step

**Authenticator**:
The application on the person's phone that generates TOTP codes. It is not a
Wallet, and it is not a Passkey. A Wallet answers a scan, and an Authenticator
answers a challenge.
_Avoid_: TOTP app, authenticator app, token generator

**TOTP Enrolment**:
The shared secret one person holds, and its state. A pending enrolment holds a
secret the person has not proved. An active enrolment is a Second Factor.
_Avoid_: Registration, setup, provisioning, binding

Note: this is a third meaning of "enrolment". A Membership puts a person in an
organization, and a DI Enrolment is the account the Scan Verifier keeps. Always
qualify the word.

**Recovery Code**:
A single-use value that stands in for an Authenticator code. Redeeming one records
the same Factor, `otp`.
_Avoid_: Backup code, one-time code, reset code

Note: a Recovery Code is not an Authorization Code, and it is not the token that
resets a forgotten password. It recovers a Second Factor and nothing else.

**Passkey**:
A key pair one person registers with this tenant, held by a device that person
controls. The device keeps the private half, and the gateway stores the public
half alone. One person can register several.
_Avoid_: WebAuthn credential, security key, authenticator, FIDO key, token

Note: the device that holds a Passkey is never an Authenticator here. That word
names the TOTP application and nothing else. Name the device itself.

**RP ID**:
The domain one Passkey binds to. The device answers a challenge under that domain
alone, so every front end of one tenant must share it.
_Avoid_: Origin, host, domain (unqualified), relying party

**MFA Requirement**:
The policy that forces a person holding no Second Factor to enrol before they
finish signing in. It does not decide whether a person is challenged. An active
Second Factor is always challenged.
_Avoid_: MFA policy, 2FA setting, MFA enforcement

**Pending Step**:
Something the gateway tells the sign-in front end to run next, before the person
finishes. It is not a Factor. A Factor is what the person already proved, and a
Pending Step is what they still owe.
_Avoid_: Method, factor, next factor, AMR

Note: this deployment names four. A person who holds an active TOTP Enrolment owes
the Authenticator challenge, `otp`. A person who holds a Passkey owes the passkey
challenge, `webauthn`. A person the MFA Requirement governs who holds no Second
Factor owes enrolment, and the two enrolments are `otp_enroll` and
`webauthn_enroll`.

A challenge step always carries the name of the Factor it asks for. The gate reads
the step name as a Factor name, so the two can never be different words.

The gateway names every step the person can run, most preferred first, and the
person runs one of them. It is a menu, not a queue. A person who holds both kinds
of Second Factor is offered both, so a device left at home never shuts that person
out of a factor that works.

A Pending Step never reaches a token. Two step names share their text with a
Factor name, `otp` and `webauthn`, and each pair stays distinct: one is owed, and
the other is proved. The word `passkey` names no step and no Factor. See
`docs/adr/0012-passkey-amr-value.md`.

**Guessing Budget**:
How many second-factor codes one person may submit inside a trailing window,
counted across every sign-in that person opens. It is separate from the count one
Login Session keeps, which ends that sign-in alone.
_Avoid_: Rate limit, throttle, lockout, attempt counter

Note: two caps, and both are needed. The per-session count ends one sign-in, and
the Guessing Budget is what makes ending a sign-in worthless. Without it, an
attacker who already holds the password answers one identifier step and one
password step, and buys a fresh set of guesses for ever.

**Consent**:
A record that one person allowed one client to receive a set of scopes. Consent
outlives the authorization request that created it.
_Avoid_: Approval, grant (see Grant), authorization

### Tokens

**Grant**:
What a client received and can still use: the scopes, the subject, and the tokens
issued from one successful authorization. Revoking a grant ends all of it.
_Avoid_: Token, session, authorization

**Resource**:
An API that accepts tokens of one tenant, named by a URN. A client asks for one at
`/authorize`, and the token comes back with that name in `aud`. The gateway
declares two: `urn:alphaomega:admin-api` and `urn:alphaomega:account-api`. A
resource server refuses a token that names another resource.
_Avoid_: Audience, API, resource server, service

**Authorization Code**:
A single-use value that a client exchanges for tokens. It is redeemed once and
never again.
_Avoid_: Code (unqualified), auth code, ticket

**Refresh Token**:
A long-lived value that a client exchanges for a new access token. Each exchange
replaces it.
_Avoid_: Renewal token, offline token

**Superseded Refresh Token**:
A refresh token that a rotation replaced. Presenting one is proof of a leak, and it
kills the whole grant.
_Avoid_: Old token, used token, stale token

### Claims

**Scope**:
A named bundle of claims a client can request. The tenant decides which scopes it
advertises.
_Avoid_: Permission, role, privilege

**Claim Mapper**:
A rule that fills one claim from one source, for one scope. It decides the claim
name and which tokens carry it.
_Avoid_: Mapper, claim rule, attribute mapping

**Assurance Level**:
How many Factors one sign-in proved, published in the `acr` claim. The gateway
declares two levels: one factor, and two or more. It says how many, never which.
_Avoid_: ACR, LOA, trust level, security level

**Signing Key**:
A key pair a tenant uses to sign tokens. Only the public half is ever published.
_Avoid_: Certificate, secret, JWK (that is an encoding, not the concept)

### Digital Identity

**Scan Verifier**:
An external service that turns a credential a person presents into a proven
identity. Digital Identity is the first one, and today the only one.
_Avoid_: Verifier (unqualified), DI, wallet service, identity provider

**QR Login**:
The flow where a person proves who they are by presenting a wallet credential,
instead of typing a password.
_Avoid_: QR sign-in, scan login, wallet login, passwordless

**QR Login Transaction**:
One QR Login in flight: the code on screen, the nonce it binds, and the result the
verifier sends back.
_Avoid_: Session, scan session, QR session, request

Note: the Scan Verifier keeps its own session identifier for one scan. That
identifier is a fourth meaning of the word "session" in this system. It is not a
Login Session, and it is not an Authn Session.

**Wallet**:
The application on the person's phone that holds the credential and answers a scan.
_Avoid_: App, holder, agent, digital wallet

**DI Enrolment**:
The account the Scan Verifier keeps for one gateway person, keyed by that person's
username.
_Avoid_: Registration, onboarding, enrollment (see Membership), provisioning
