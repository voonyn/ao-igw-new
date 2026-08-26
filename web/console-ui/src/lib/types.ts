// AlphaOmega Console — domain types (mirrors the goose migrations / schema shapes)

export type EntityState = 1 | 2 | 3; // Active | Inactive | Removed
export type UserState = 1 | 2 | 3 | 4 | 5; // Active | Inactive | Deleted | Locked | Initial
export type AppType = 1 | 2 | 3; // OIDC | SAML | API
export type KeyState = 1 | 2 | 3; // Active | Inactive | Retired
export type KeyUse = 1 | 2; // sig | enc

export interface TenantDomain {
  domain: string;
  isPrimary: boolean;
  isVerified: boolean;
  state: number;
}

export interface Tenant {
  id: string;
  name: string;
  state: EntityState;
  defaultOrgId: string | null;
  created: string;
  domains: TenantDomain[];
}

export interface Org {
  id: string;
  tenantId: string;
  name: string;
  state: EntityState;
  created: string;
  isDefault?: boolean;
}

export interface Project {
  id: string;
  tenantId: string;
  orgId: string;
  name: string;
  state: EntityState;
  created: string;
  roleAssertion: boolean;
  roleCheck: boolean;
  hasProjectCheck: boolean;
  privateLabeling: number;
}

export interface OidcConfig {
  clientId: string;
  authnMethod: string;
  secretSet: boolean;
  secretExpires: string | null;
  subjectType: string;
  parRequired: boolean;
  defaultMaxAge: number | null;
  isFirstParty: boolean;
  redirectUris: string[];
  postLogoutUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scopeIds: string[];
  crypto: Record<string, string> | null;
  authn: Record<string, string> | null;
  binding: Record<string, string> | null;
  ciba: Record<string, string> | null;
  federation: Record<string, string> | null;
}

export interface App {
  id: string;
  tenantId: string;
  projectId: string;
  /** Parent project's name, joined server-side — a paged view holds one page and
   * cannot resolve `projectId` against a projects collection. */
  projectName: string;
  /** Parent project's organization. The write gate keys on it, so it is
   * authorization input rather than decoration. */
  orgId: string;
  name: string;
  appType: AppType;
  state: EntityState;
  created: string;
  oidc: OidcConfig | null;
}

export interface Human {
  firstName: string;
  lastName: string;
  displayName: string;
  lang: string;
  email: string;
  emailVerified: boolean;
  phone: string | null;
  phoneVerified: boolean;
  pwdChangeRequired: boolean;
  pwdChangedAt: string | null;
}

export interface User {
  id: string;
  tenantId: string;
  orgId: string;
  username: string;
  userType: 1 | 2; // human | machine
  state: UserState;
  created: string;
  /** Most recent successful authentication; "" when the user has never
   * authenticated, which renders as "Never". */
  lastAuth: string;
  mfaEnabled: boolean; // has an active TOTP factor OR a passkey (add-webauthn-passkeys)
  human?: Human;
}

export interface TenantMember {
  tenantId: string;
  userId: string;
  /** Member's display name, joined server-side. */
  userName: string;
  roles: string[];
  created: string;
}

export interface OrgMember {
  tenantId: string;
  orgId: string;
  userId: string;
  /** Member's display name, joined server-side. Empty on the `/me` payload,
   * which reports the caller's own memberships and names them at the top level. */
  userName: string;
  roles: string[];
  created: string;
}

export interface ProviderConfig {
  issuer: string;
  state: number;
  requirePkce: boolean;
  refreshRotation: boolean;
  authCodeLifetime: number;
  accessTokenType: string; // 'JWT' | 'Opaque'
  accessTokenLifetime: number;
  idTokenLifetime: number;
  refreshTokenLifetime: number | null;
  /** RFC 8707 resource identifiers a client of this tenant may ask for. Read
   * only: the admin API's own identifier is in here, and removing it would leave
   * no way to mint the token that would put it back. */
  resourceIndicators: string[];
}

/** A PATCH body for the provider config. Every field is optional: an omitted
 * field is left alone. `issuer`, `state` and `resourceIndicators` are absent on
 * purpose — the API does not accept writes to them. */
export interface ProviderConfigBody {
  authCodeLifetime?: number;
  accessTokenLifetime?: number;
  idTokenLifetime?: number;
  refreshTokenLifetime?: number;
  requirePkce?: boolean;
  refreshRotation?: boolean;
  /** 'JWT' only. The API accepts the field and refuses 'Opaque', because the
   * protocol engine does not build a provider that issues one. */
  accessTokenType?: string;
}

export interface Key {
  id: string;
  tenantId: string;
  use: KeyUse;
  alg: string;
  state: KeyState;
  activeAt: string | null;
  expiresAt: string | null;
  created: string;
  /** Last write to the row — when a rotation demoted or promoted this key.
   * expiresAt is the future grace deadline, not the moment it stopped signing. */
  updated: string;
}

export interface Factor {
  amr: string;
  time: string;
}

export interface SessionLink {
  protocol: number;
  appId: string;
  ref: string;
}

export interface LoginSession {
  id: string;
  tenantId: string;
  userId: string;
  /** Owner's display name and organization, joined server-side. `orgId` is what
   * the force-logout control gates on, so it is authorization input, not decor. */
  userName: string;
  orgId: string;
  state: 1 | 2;
  created: string;
  expires: string;
  /** IP and user agent RECORDED AT MINT — not last-seen — decoded from the
   * session blob. Both are "" when that row's blob could not be decoded, which
   * renders as an explicit unknown marker rather than a blank cell. */
  ip: string;
  ua: string;
  factors: Factor[];
  /** One per relying party the session authenticated to. Deliberately not a
   * grant count: grants die on revoke/expiry and multiply on refresh rotation. */
  links: SessionLink[];
}

export interface Grant {
  id: string;
  tenantId: string;
  appId: string;
  /** Client's application name, joined server-side; empty when the client is gone. */
  appName: string;
  subject: string | null;
  /** Subject's display name, joined server-side; empty for a client-credentials
   * grant, which has no subject to name. */
  subjectName: string;
  loginSessionId: string | null;
  kind: string;
  created: string;
  expires: string;
}

export interface BootstrapArtifact {
  label: string;
  detail: string;
}

export interface Bootstrap {
  id: number;
  tenantId: string;
  version: string;
  appliedAt: string;
  artifacts: BootstrapArtifact[];
}

/**
 * One page of a growth-bearing list read.
 *
 * `items` is the gateway envelope's `data`, and the four numbers are its `meta`
 * (`response.Meta` in `internal/api/http/response/response.go`) — keep the two in
 * sync. The BFF merges them into this one shape.
 *
 * Every page carries `total` and `totalPages`, so a pager can address page 7
 * before an operator has walked to page 6. See
 * `docs/adr/0007-offset-pagination-for-admin-lists.md`.
 */
export interface Page<T> {
  items: T[];
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

/**
 * The console's shared, eagerly-loaded state.
 *
 * Only BOUNDED reads live here. The growth-bearing collections — organizations,
 * projects, applications, users, members, sessions, grants — were removed with
 * paginate-admin-list-api: a store that holds "every row" is exactly what cannot
 * survive paging, and holding page one instead is a store that quietly lies
 * about the size of the tenant. Those now belong to the view that renders them,
 * one page at a time, via `usePagedList`.
 *
 * `tenants` holds the single resolved tenant (the multi-tenant list is SYSTEM
 * scope and deferred); `keys` is a tenant's signing keys, bounded by rotation
 * policy; `providerConfigs` is one config per tenant.
 */
export interface Db {
  tenants: Tenant[];
  keys: Key[];
  providerConfigs: Record<string, ProviderConfig>;
}

// ---- legacy / preview sample data (the v1 "Meridian Dynamics" enterprise) ----

export interface LegacyRole {
  id: string;
  name: string;
  desc: string;
  members: number;
  color?: string;
  system: boolean;
  perms: Record<string, string[]>;
}

export interface LegacyUser {
  id: string;
  name: string;
  email: string;
  dept: string;
  title: string;
  roles: string[];
  status: string;
  mfa: string;
  lastActive: string;
  created: string;
  location: string;
  sessions: number;
}

export interface LegacyApp {
  id: string;
  name: string;
  users: number;
  tile: string;
  signOn: string;
  provisioning: boolean;
  lastSync: string;
  owner: string;
  groups: string[];
  status: string;
}

export interface LegacyGroup {
  id: string;
  name: string;
  members: number;
  source: string;
  roles: string[];
  apps: string[];
  owner: string;
  synced: string;
  expires?: string;
  desc: string;
}
