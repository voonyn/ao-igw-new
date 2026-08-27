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
_Avoid_: Method, credential, step, AMR

Note: a factor name is a value of the AMR registry of RFC 8176 where one fits. A
password is `pwd`. Where the registry lists no value, this deployment names the
factor itself, and the registry permits that. A scan is `vc`.

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
