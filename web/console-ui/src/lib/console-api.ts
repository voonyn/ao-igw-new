// Client-side loader for live console data.
//
// Every read goes to the same-origin BFF (`/api/admin/*`), which attaches the
// access token server-side and proxies to the gateway `/api/v1/admin/*`. The
// browser never sees a token. The per-resource responses are assembled into the
// `Db` shape the existing views already consume, so the view components are
// unchanged. A `401` means the session is gone — the caller should send the user
// back to login.

import type {
  Bootstrap,
  Db,
  Grant,
  Key,
  LoginSession,
  Org,
  OrgMember,
  Page,
  Project,
  ProviderConfig,
  ProviderConfigBody,
  Tenant,
  TenantDomain,
  TenantMember,
  App as AppType,
  User,
} from "./types";

export interface OrgRef {
  id: string;
  name: string;
}

export interface Me {
  userId: string;
  username: string;
  displayName: string;
  email: string;
  tenant: Tenant;
  isTenantManager: boolean;
  tenantRoles: string[];
  orgMemberships: OrgMember[];
  accessibleOrgs: OrgRef[];
}

/** Why a collection has no data. `forbidden` and `missing` are deliberately not
 * collapsed: an operator lacking a role needs a different sentence than a
 * subsystem that isn't configured, and both differ from a request that broke. */
export type CollectionStatus =
  | { state: "ok" }
  | { state: "forbidden" }
  | { state: "missing" }
  | { state: "error"; message: string };

/** The reads the console loads eagerly and shares. Every one of them is BOUNDED:
 * the growth-bearing collections moved into the views that page them, and took
 * their load status with them (a view that owns its fetch owns its error). */
export const COLLECTION_KEYS = ["keys", "provider", "tenant", "bootstrap"] as const;

export type CollectionKey = (typeof COLLECTION_KEYS)[number];

export interface ConsoleData {
  me: Me;
  db: Db;
  bootstrap: Bootstrap | null;
  status: Record<CollectionKey, CollectionStatus>;
}

/** Thrown on a 401 from the BFF so the caller can redirect to login. */
export class UnauthorizedError extends Error {
  constructor() {
    super("unauthenticated");
    this.name = "UnauthorizedError";
  }
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { cache: "no-store", credentials: "same-origin" });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
  return (await res.json()) as T;
}

/** A read that may legitimately have no data, with the reason preserved. */
export type Outcome<T> = { ok: true; data: T } | { ok: false; reason: "forbidden" | "missing" };

/**
 * Like getJson but reports 403 and 404 as outcomes instead of throwing. There is
 * no `fallback` parameter on purpose: collapsing both into one empty value is
 * what made "you lack IAM_OWNER" and "nothing here" indistinguishable.
 */
export async function getOptional<T>(path: string): Promise<Outcome<T>> {
  const res = await fetch(path, { cache: "no-store", credentials: "same-origin" });
  if (res.status === 401) throw new UnauthorizedError();
  if (res.status === 403) return { ok: false, reason: "forbidden" };
  if (res.status === 404) return { ok: false, reason: "missing" };
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
  return { ok: true, data: (await res.json()) as T };
}

// ── Paged list reads ──────────────────────────────────────────────────────────
//
// Every growth-bearing list read answers with a `Page<T>` envelope rather than a
// bare array, and accepts `page`, `limit`, and `orgId`. The window is an offset:
// the console shows a pager, and an operator names a page and goes to it.
//
// A row written while an operator reads page 3 shifts every later row by one
// place, so a row can appear twice or not at all. A refresh corrects the view.
// See `docs/adr/0007-offset-pagination-for-admin-lists.md`.

/** The narrowing a list read asks the SERVER for: a sort key from that list's
 * allowlist, a direction, a prefix search term, and the typed filters. Every one
 * is optional and absent means "no opinion" — the list keeps the order and scope
 * it is served in today.
 *
 * These are query parameters and nothing else. Narrowing a page in the client
 * was the defect this replaces: it searched the rows that happened to have been
 * loaded, so a row on page four was unfindable and `total` described a
 * collection the table did not show. */
export interface ListQuery {
  /** A key from the list's allowlist (`created`, `name`, `username`, …). An
   * unknown key is refused with 422 naming the permitted set — never ignored. */
  sort?: string;
  dir?: "asc" | "desc";
  /** Prefix search term. Each list declares which fields it matches; the control
   * that collects it states them. */
  q?: string;
  /** Entity/user/session state. Absent excludes soft-deleted rows on the
   * resources that have them. */
  state?: number;
  /** User type (1 human, 2 machine). */
  type?: number;
}

/** Options for a paged list read. Omit `page` for page 1. `orgId` narrows the
 * query server-side; narrowing the returned page in the client instead would
 * shrink it below the requested limit and misreport a full list as exhausted.
 * `userId` narrows the reads that have a subject (sessions, grants, memberships)
 * the same way. */
export interface PageOpts extends ListQuery {
  limit?: number;
  page?: number;
  orgId?: string | null;
  userId?: string;
}

function pageQuery(opts: PageOpts = {}): string {
  const q = new URLSearchParams();
  if (opts.limit) q.set("limit", String(opts.limit));
  if (opts.page && opts.page > 1) q.set("page", String(opts.page));
  if (opts.orgId) q.set("orgId", opts.orgId);
  if (opts.userId) q.set("userId", opts.userId);
  if (opts.sort) q.set("sort", opts.sort);
  if (opts.dir) q.set("dir", opts.dir);
  if (opts.q) q.set("q", opts.q);
  // 0 is a meaningful state on no list, but writing the guard as a null-check
  // keeps it true if one ever adds one.
  if (opts.state !== undefined) q.set("state", String(opts.state));
  if (opts.type !== undefined) q.set("type", String(opts.type));
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** Reads one page of a list endpoint. Reports 403/404 as outcomes rather than
 * throwing, so a paged view can say which role the list needs instead of
 * rendering an empty table — the same reasoning as `getOptional`. */
export async function getPage<T>(path: string, opts: PageOpts = {}): Promise<Outcome<Page<T>>> {
  return getOptional<Page<T>>(`${path}${pageQuery(opts)}`);
}

/** A paged list read: same shape for every growth-bearing resource, so one hook
 * can drive them all. */
export type PageReader<P extends Page<unknown>> = (o?: PageOpts) => Promise<Outcome<P>>;

/** The page sizes the size control offers. The largest is the largest the
 * gateway serves (`middlewares.maxPageLimit`), so no selection is a size the
 * gateway would clamp. Every control offering a page size reads its options from
 * here. */
export const PAGE_SIZES = [10, 50, 100] as const;

/** Page size for an exhaustive read. It is the largest size the gateway serves
 * (`middlewares.maxPageLimit`), so the walk takes the fewest round trips. A
 * larger number is clamped, not served, which is why the picker walks pages
 * instead of asking for one page the size of the collection. */
export const WALK_PAGE = 100;

/** How many rows a picker holds. A `<select>` has no pager, so it shows a short
 * head of the collection and the operator narrows it by typing: the search is a
 * request parameter, so a match on the thousandth row is found. Ten rows fit on
 * screen without scrolling and cost one small request. */
export const PICKER_PAGE = 10;

/**
 * One exhaustive read: read page 1, then read the pages after it until the
 * collection is exhausted.
 *
 * It backs an export and the membership exclusion set. A CSV has no second page
 * and an exclusion set that stopped early would offer a duplicate the write then
 * refuses, so both read the whole collection under the ACTIVE narrowing.
 *
 * There is no page bound. A picker used to share this walk and needed one; a
 * picker now reads one short page and searches instead. What is left must be
 * complete to be correct.
 *
 * The answer keeps page 1's shape and its `total`. The caller compares the rows
 * it holds against that `total`, so a walk that fails mid-way reports itself
 * incomplete rather than as the end.
 */
export async function readAllPages<P extends Page<unknown>>(read: PageReader<P>, opts: PageOpts = {}): Promise<Outcome<P>> {
  const first = await read({ ...opts, limit: WALK_PAGE, page: 1 });
  if (!first.ok) return first;

  let items = first.data.items ?? [];
  const last = first.data.totalPages ?? 1;
  for (let page = 2; page <= last; page++) {
    const next = await read({ ...opts, limit: WALK_PAGE, page });
    if (!next.ok) break;
    items = items.concat(next.data.items ?? []);
  }
  return { ok: true, data: { ...first.data, items } };
}

/** The paged collection reads, one per growth-bearing resource. Each is a stable
 * module-level reference, which is what lets `usePagedList` take one as a
 * dependency without refetching on every render. */
export const pages = {
  orgs: (o?: PageOpts) => getPage<Org>("/api/admin/organizations", o),
  projects: (o?: PageOpts) => getPage<Project>("/api/admin/projects", o),
  apps: (o?: PageOpts) => getPage<AppType>("/api/admin/applications", o),
  users: (o?: PageOpts) => getPage<User>("/api/admin/users", o),
  sessions: (o?: PageOpts) => getPage<LoginSession>("/api/admin/sessions", o),
  grants: (o?: PageOpts) => getPage<Grant>("/api/admin/grants", o),
  /** The tenant's administrator roster. Tenant-scoped: an org manager is
   * answered with an empty page rather than a refusal. */
  tenantMembers: (o?: PageOpts) => getPage<TenantMember>("/api/admin/members/tenant", o),
  orgMembers: (o?: PageOpts) => getPage<OrgMember>("/api/admin/members/org", o),
};

/** Every scope a named user holds a membership in, with the roles each grants.
 *
 * Both halves come back whole rather than paged: one person's memberships are
 * bounded by the organizations they belong to, which is not a growth curve the
 * way a tenant's user list is. */
export interface UserMemberships {
  tenantMemberships: TenantMember[];
  orgMemberships: OrgMember[];
}

export const userMemberships = (id: string) =>
  getOptional<UserMemberships>(`/api/admin/users/${encodeURIComponent(id)}/memberships`);

/** Reads just the `total` of one collection. Every page carries `meta.total` —
 * the count taken server-side by the same `COUNT(*)` whatever the size — so the
 * smallest page answers it, and the page asked for is one row. This is how the
 * overview tiles, the sidebar badges and the detail-page counts are sourced now
 * that no view holds a whole collection to measure. A caller that already holds
 * a page reads `page.total` and does not call this at all.
 *
 * A read the caller may not make counts as zero: a badge is not the place to
 * raise a permission error the view itself will state. */
export async function getTotal(path: string, opts: PageOpts = {}): Promise<number> {
  const out = await getPage<unknown>(path, { ...opts, limit: 1 });
  return out.ok ? (out.data.total ?? 0) : 0;
}

// settled turns one allSettled result into (value, status). A rejection keeps the
// collection's own error rather than taking the whole console down with it.
function settled<T>(r: PromiseSettledResult<T>, fallback: T): [T, CollectionStatus] {
  if (r.status === "fulfilled") return [r.value, { state: "ok" }];
  if (r.reason instanceof UnauthorizedError) throw r.reason;
  return [fallback, { state: "error", message: r.reason instanceof Error ? r.reason.message : String(r.reason) }];
}

// settledOptional is `settled` for the reads that may answer 403/404.
function settledOptional<T>(r: PromiseSettledResult<Outcome<T>>, fallback: T): [T, CollectionStatus] {
  const [out, st] = settled(r, { ok: true, data: fallback } as Outcome<T>);
  if (st.state !== "ok") return [fallback, st];
  return out.ok ? [out.data, { state: "ok" }] : [fallback, { state: out.reason }];
}

/**
 * Loads the console's shared state: who the caller is, which organizations they
 * may read, and the bounded singletons (signing keys, provider config, tenant,
 * bootstrap record).
 *
 * It deliberately loads NO list collection. Every growth-bearing read is paged
 * and belongs to the view that renders it — a shared store cannot hold a page
 * without either misreporting the tenant's size or unbounding itself again, and
 * the accessible-org list the switcher needs already rides on `/me`.
 */
export async function loadConsoleData(): Promise<ConsoleData> {
  const me = await getJson<Me>("/api/admin/me");
  const tenantId = me.tenant.id;

  const settledAll = await Promise.allSettled([
    getOptional<Key[]>("/api/admin/keys"),
    getOptional<ProviderConfig>("/api/admin/provider"),
    getOptional<Tenant>("/api/admin/tenant"),
    getOptional<Bootstrap>("/api/admin/bootstrap"),
  ] as const);

  const [keys, sKeys] = settledOptional(settledAll[0], [] as Key[]);
  const [provider, sProvider] = settledOptional<ProviderConfig | null>(settledAll[1], null);
  const [resolved, sTenant] = settledOptional<Tenant | null>(settledAll[2], null);
  const [bootstrap, sBootstrap] = settledOptional<Bootstrap | null>(settledAll[3], null);

  const db: Db = {
    // The console is bound to one tenant; the multi-tenant list is SYSTEM scope
    // and deferred. `tenants` holds only the resolved tenant.
    tenants: [resolved ?? me.tenant],
    keys,
    providerConfigs: provider ? { [tenantId]: provider } : {},
  };

  return {
    me,
    db,
    bootstrap,
    status: { keys: sKeys, provider: sProvider, tenant: sTenant, bootstrap: sBootstrap },
  };
}

// ── Single-resource reads ─────────────────────────────────────────────────────
//
// A detail route reads its record by id rather than re-deriving it from list
// state, so it survives a filter change, a paged list, and a cold tab. A 403 and
// a 404 both surface as `{ok:false}` — the API already answers 404 for a record
// outside the caller's scope, and the route renders not-found either way.

export const byId = {
  user: (id: string) => getOptional<User>(`/api/admin/users/${encodeURIComponent(id)}`),
  org: (id: string) => getOptional<Org>(`/api/admin/organizations/${encodeURIComponent(id)}`),
  project: (id: string) => getOptional<Project>(`/api/admin/projects/${encodeURIComponent(id)}`),
  app: (id: string) => getOptional<AppType>(`/api/admin/applications/${encodeURIComponent(id)}`),
};

// ── Scopes & claim mappers (the console's first writable surface) ─────────────

export interface Scope {
  id: string;
  name: string;
  displayName: string;
  description: string;
  isEnabled: boolean;
  isDefault: boolean;
  isBuiltin: boolean;
  mapperCount: number;
}

export interface Mapper {
  id: string;
  scopeId: string;
  claimName: string;
  sourceType: number; // 1=std attr 2=user bag 3=membership 4=static
  sourceKey: string;
  sourceValue?: unknown;
  inIdToken: boolean;
  inUserInfo: boolean;
  inAccessToken: boolean;
}

/** Body for creating/updating a scope. */
export interface ScopeBody {
  name: string;
  displayName: string;
  description: string;
  isEnabled: boolean;
  isDefault: boolean;
}

/** Body for creating/updating a claim mapper. */
export interface MapperBody {
  claimName: string;
  sourceType: number;
  sourceKey: string;
  sourceValue?: unknown;
  inIdToken: boolean;
  inUserInfo: boolean;
  inAccessToken: boolean;
}

/** Thrown on a non-2xx mutation; `code` is the gateway's error string (e.g. protected_claim). */
export class MutationError extends Error {
  constructor(
    public code: string,
    public status: number,
  ) {
    super(code);
    this.name = "MutationError";
  }
}

async function mutate<T>(path: string, method: "POST" | "PUT" | "PATCH" | "DELETE", body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) throw new UnauthorizedError();
  const text = await res.text();
  // Status first: a proxy's non-JSON 502 must surface as a 502, not a SyntaxError.
  if (!res.ok) throw new MutationError(errorCode(text) ?? `http_${res.status}`, res.status);
  return (text ? (JSON.parse(text) as unknown) : {}) as T;
}

// errorCode pulls the gateway's error string out of a body that may not be JSON.
function errorCode(text: string): string | null {
  if (!text) return null;
  try {
    return (JSON.parse(text) as { error?: string }).error ?? null;
  } catch {
    return null;
  }
}

/** Client for the scope/mapper admin API, proxied through the same-origin BFF. */
export const scopesApi = {
  // Optional, not throwing: the read is IAM_OWNER-only, so a refusal is a
  // routine outcome the view names — not an Error whose message it regex-sniffs.
  list: () => getOptional<Scope[]>("/api/admin/scopes"),
  create: (b: ScopeBody) => mutate<Scope>("/api/admin/scopes", "POST", b),
  update: (id: string, b: ScopeBody) => mutate<Scope>(`/api/admin/scopes/${id}`, "PATCH", b),
  remove: (id: string) => mutate<{ ok: boolean }>(`/api/admin/scopes/${id}`, "DELETE"),
  mappers: (id: string) => getJson<Mapper[]>(`/api/admin/scopes/${id}/mappers`),
  createMapper: (id: string, b: MapperBody) => mutate<Mapper>(`/api/admin/scopes/${id}/mappers`, "POST", b),
  updateMapper: (id: string, b: MapperBody) => mutate<Mapper>(`/api/admin/mappers/${id}`, "PATCH", b),
  removeMapper: (id: string) => mutate<{ ok: boolean }>(`/api/admin/mappers/${id}`, "DELETE"),
};

// ── Notifications (delivery settings + message templates) ─────────────────────

export interface NotificationSettings {
  transport: string; // "smtp" | "log"
  smtpHost: string;
  smtpPort: number;
  smtpUsername: string;
  passwordSet: boolean; // the SMTP password is write-only; this reports presence
  fromAddress: string;
  fromName: string;
  tlsMode: string; // "starttls" | "tls" | "none"
  sendTimeoutSeconds: number;
  configured: boolean;
}

/** Settings PATCH body. Omit smtpPassword to keep the stored value; "" clears it. */
export interface NotificationSettingsBody {
  transport: string;
  smtpHost: string;
  smtpPort: number;
  smtpUsername: string;
  smtpPassword?: string;
  fromAddress: string;
  fromName: string;
  tlsMode: string;
  sendTimeoutSeconds: number;
}

export interface NotificationTemplateInfo {
  key: string;
  isOverride: boolean; // a deletable override exists at the current scope
  source: string; // effective origin at the scope: "org" | "tenant" | "embedded"
  updatedAt: string | null;
}

export interface NotificationTemplate {
  key: string;
  isOverride: boolean;
  subject: string;
  bodyText: string;
  bodyHtml: string;
}

export interface NotificationTemplateBody {
  subject: string;
  bodyText: string;
  bodyHtml: string;
}

export interface RenderedTemplate {
  subject: string;
  text: string;
  html: string;
}

// ── Auth policy (lockout / password / recovery — move-auth-settings-to-db) ─────

/** Effective (resolved) auth policy plus, per field, whether the value is set at
 * the read scope (overridden) or inherited from the level below. Durations are
 * seconds. `orgId` is "" for the tenant default. */
export interface AuthPolicy {
  orgId: string;
  lockoutThreshold: number;
  lockoutWindowSeconds: number;
  lockoutCooldownSeconds: number;
  pwMinLength: number;
  pwMinClasses: number;
  pwDenyList: string[];
  pwCheckBreach: boolean;
  recoveryResetTtlSeconds: number;
  recoveryVerifyTtlSeconds: number;
  mfaRequired: boolean;
  // Keyed by the field names above; true = set at this scope, false = inherited.
  overridden: Record<string, boolean>;
}

/** PUT body. Each field is optional: omit or null to inherit (the level below
 * governs); a value sets it explicitly (a stored 0/false is an explicit setting,
 * e.g. lockoutThreshold 0 disables lockout). */
export interface AuthPolicyBody {
  lockoutThreshold?: number | null;
  lockoutWindowSeconds?: number | null;
  lockoutCooldownSeconds?: number | null;
  pwMinLength?: number | null;
  pwMinClasses?: number | null;
  pwDenyList?: string[] | null;
  pwCheckBreach?: boolean | null;
  recoveryResetTtlSeconds?: number | null;
  recoveryVerifyTtlSeconds?: number | null;
  mfaRequired?: boolean | null;
}

// authBase is the auth-policy path for a scope: an empty orgId is the tenant
// default (the tenant route); a real org id is that org's override route.
const authBase = (orgId?: string) =>
  orgId ? `/api/admin/orgs/${encodeURIComponent(orgId)}/settings/auth` : `/api/admin/settings/auth`;

/** Client for the auth-policy settings admin API, proxied through the BFF. An
 * optional orgId targets an organization's override; omitted/empty targets the
 * tenant default. reset (DELETE) is org-scope only — it removes the override so
 * the org falls back to the tenant default. */
export const authPolicyApi = {
  // `getOptional`, not `getJson`: a 403 here is a permission answer the view has
  // to say out loud, and `getJson` flattens it into a generic Error.
  get: (orgId?: string) => getOptional<AuthPolicy>(authBase(orgId)),
  update: (b: AuthPolicyBody, orgId?: string) => mutate<AuthPolicy>(authBase(orgId), "PUT", b),
  reset: (orgId: string) => mutate<{ ok: boolean }>(authBase(orgId), "DELETE"),
};

/** Client for the provider-config write. The read is part of the eager console
 * load (`/api/admin/provider` above), so there is no `get` here. Only the six
 * runtime knobs are writable; the API rejects anything else. */
export const providerApi = {
  update: (b: ProviderConfigBody) => mutate<ProviderConfig>("/api/admin/provider", "PATCH", b),
};

// ── Audit log ─────────────────────────────────────────────────────────────────

export interface AuditEvent {
  id: string;
  actor?: string;
  action: string;
  entityType: string;
  entityId?: string;
  result: string; // "success" | "failure"
  ip?: string;
  userAgent?: string;
  metadata?: unknown;
  createdAt: string; // RFC3339
}

/** The audit feed pages the same way every other list does. */
export type AuditPage = Page<AuditEvent>;

/** Filter/pagination for an audit read. All fields optional; the server ignores
 * empty ones and returns the tenant's whole feed, newest first. */
export interface AuditQuery {
  actor?: string;
  action?: string;
  entityType?: string;
  entityId?: string;
  from?: string; // RFC3339
  to?: string; // RFC3339
  limit?: number;
  page?: number;
}

/** Client for the audit read API, proxied through the BFF. A non-manager 403 is
 * returned as an outcome so the view can say which role the feed needs instead
 * of rendering an empty log. */
export const auditApi = {
  list: (q: AuditQuery = {}): Promise<Outcome<AuditPage>> => {
    const p = new URLSearchParams();
    if (q.actor) p.set("actor", q.actor);
    if (q.action) p.set("action", q.action);
    if (q.entityType) p.set("entity_type", q.entityType);
    if (q.entityId) p.set("entity_id", q.entityId);
    if (q.from) p.set("from", q.from);
    if (q.to) p.set("to", q.to);
    if (q.limit) p.set("limit", String(q.limit));
    if (q.page && q.page > 1) p.set("page", String(q.page));
    const qs = p.toString();
    return getOptional<AuditPage>(`/api/admin/audit${qs ? `?${qs}` : ""}`);
  },
};

// ── Resource writes (add-admin-write-api) ─────────────────────────────────────
//
// The console's management write surface: role-gated, tenant-scoped mutations for
// users, organizations, projects, applications (incl. client-secret rotation), and
// members. All go through the same-origin BFF (which already forwards mutations)
// and reuse the `mutate` helper + MutationError. Views reload via the store after a
// write rather than consuming these responses, so most return types are loose.

export interface CreateUserBody {
  orgId: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  displayName: string;
  lang: string;
  password: string;
  emailVerified: boolean;
}

export interface UpdateUserBody {
  firstName: string;
  lastName: string;
  displayName: string;
  lang: string;
  phone: string;
}

export const usersApi = {
  create: (b: CreateUserBody) => mutate("/api/admin/users", "POST", b),
  update: (id: string, b: UpdateUserBody) => mutate(`/api/admin/users/${id}`, "PATCH", b),
  activate: (id: string) => mutate(`/api/admin/users/${id}/activate`, "POST"),
  deactivate: (id: string) => mutate(`/api/admin/users/${id}/deactivate`, "POST"),
  unlock: (id: string) => mutate(`/api/admin/users/${id}/unlock`, "POST"),
  passwordReset: (id: string) => mutate(`/api/admin/users/${id}/password-reset`, "POST"),
  resetMfa: (id: string) => mutate(`/api/admin/users/${id}/mfa`, "DELETE"),
  remove: (id: string) => mutate(`/api/admin/users/${id}`, "DELETE"),
};

/** One passkey of one user, as the gateway's `passkey.View` answers it. `id` is
 * the credential id in the base64url spelling the browser uses — a public handle
 * every assertion sends in the clear, never a credential. No public key reaches
 * this shape. `lastUsedAt` is absent until the passkey signs the person in once. */
export interface Passkey {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
}

/** A person's passkeys, read and revoked by an administrator.
 *
 * There is no `register`. A passkey belongs to whoever holds the device, so the
 * ceremony runs in the portal under that person's own token — no privilege here
 * enrolls a factor for somebody else.
 *
 * The two calls sit behind two gates. `list` runs the read gate — the one that
 * answered the user list and the account record — so every administrator reads
 * it. `revoke` runs the write gate, which narrows to the organization of the
 * account.
 *
 * `list` is optional, not throwing: a refusal is a routine outcome the view
 * names rather than an Error it sniffs. The list is bounded (ten per person) and
 * answers whole, so it carries no pager. */
export const passkeysApi = {
  list: (userId: string) => getOptional<Passkey[]>(`/api/admin/users/${encodeURIComponent(userId)}/passkeys`),
  revoke: (userId: string, id: string) =>
    mutate<void>(`/api/admin/users/${encodeURIComponent(userId)}/passkeys/${encodeURIComponent(id)}`, "DELETE"),
};

/** Administrative force-logout (add-admin-force-logout). Stronger than a user's
 * own sign-out: the grants go too, offline_access included, so no refresh token
 * survives. Already-issued access tokens live out their TTL at the relying party. */
export const sessionsApi = {
  revoke: (id: string) => mutate<{ ok: boolean }>(`/api/admin/sessions/${id}`, "DELETE"),
  revokeForUser: (userId: string) => mutate<{ ok: boolean }>(`/api/admin/users/${userId}/sessions`, "DELETE"),
};

export interface OrgBody {
  name: string;
}

/** Tenant domains. IAM_OWNER-only, and `remove` is a soft delete — the row flips
 * to inactive, so the globally unique domain is not freed for another tenant to
 * claim. Neither call touches DNS, TLS, or the reverse proxy. */
export const domainsApi = {
  add: (domain: string) => mutate<TenantDomain>("/api/admin/tenant/domains", "POST", { domain }),
  remove: (domain: string) => mutate<void>(`/api/admin/tenant/domains/${encodeURIComponent(domain)}`, "DELETE"),
};

export const orgsApi = {
  create: (b: OrgBody) => mutate("/api/admin/organizations", "POST", b),
  update: (id: string, b: OrgBody) => mutate(`/api/admin/organizations/${id}`, "PATCH", b),
  remove: (id: string) => mutate(`/api/admin/organizations/${id}`, "DELETE"),
};

export interface ProjectSettings {
  roleAssertion: boolean;
  roleCheck: boolean;
  hasProjectCheck: boolean;
  privateLabeling: number;
}

export interface CreateProjectBody extends ProjectSettings {
  orgId: string;
  name: string;
}

export interface UpdateProjectBody extends ProjectSettings {
  name: string;
}

export const projectsApi = {
  create: (b: CreateProjectBody) => mutate("/api/admin/projects", "POST", b),
  update: (id: string, b: UpdateProjectBody) => mutate(`/api/admin/projects/${id}`, "PATCH", b),
  remove: (id: string) => mutate(`/api/admin/projects/${id}`, "DELETE"),
};

export interface AppOidcBody {
  clientId?: string;
  tokenAuthnMethod: string;
  subjectType: string;
  parRequired: boolean;
  redirectUris: string[];
  postLogoutUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scopeIds: string[];
}

export interface CreateAppBody {
  projectId: string;
  name: string;
  appType: number;
  oidc: AppOidcBody | null;
}

export interface UpdateAppBody {
  name: string;
  oidc: AppOidcBody | null;
}

/** The freshly-minted client secret, returned exactly once at rotation. */
export interface SecretRotationResult {
  clientId: string;
  secret: string;
}

export const appsApi = {
  create: (b: CreateAppBody) => mutate("/api/admin/applications", "POST", b),
  update: (id: string, b: UpdateAppBody) => mutate(`/api/admin/applications/${id}`, "PATCH", b),
  remove: (id: string) => mutate(`/api/admin/applications/${id}`, "DELETE"),
  rotateSecret: (id: string) => mutate<SecretRotationResult>(`/api/admin/applications/${id}/rotate-secret`, "POST"),
};

/** An empty orgId targets the tenant membership; a non-empty one an org. */
export interface MemberBody {
  userId?: string;
  orgId: string;
  roles: string[];
}

/** Invitation body — mirrors `user.InvitationInput`. `orgId` is required for the
 * same reason `MemberBody`'s is: an invitation IS a membership grant. */
export interface InvitationBody {
  email: string;
  orgId: string;
  roles: string[];
  username?: string;
  displayName?: string;
}

export const membersApi = {
  add: (b: MemberBody) => mutate("/api/admin/members", "POST", b),
  invite: (b: InvitationBody) => mutate("/api/admin/invitations", "POST", b),
  updateRoles: (userId: string, b: MemberBody) => mutate(`/api/admin/members/${userId}`, "PATCH", b),
  remove: (userId: string, orgId: string) =>
    mutate(`/api/admin/members/${userId}${orgId ? `?orgId=${encodeURIComponent(orgId)}` : ""}`, "DELETE"),
};

// One error code, one sentence — every view resolves its message from here, so
// `forbidden` cannot say four different things depending on which page raised it.
// That includes the views that refuse BEFORE they ask: a role gate the console
// evaluates itself (audit, notifications, auth policy) goes through
// `describeStatus` too, so a pre-emptive refusal and a 403 read identically.
const MUTATION_MESSAGES: Record<string, string> = {
  forbidden: "You don't have permission to make this change.",
  // The read-side twin of `forbidden`, and the home for the pre-emptive gate: a
  // view the console refuses before it asks (the caller holds none of the roles
  // the page needs) says the same thing as one the gateway refuses with a 403.
  forbidden_read: "You don't have permission to view this.",
  not_found: "That item no longer exists, or is outside your access.",
  name_conflict: "That name or identifier is already taken.",
  // The username is unique inside one tenant. A create and an update both answer
  // it, and it names the one field the operator has to change.
  duplicate_username: "Another account of this tenant already holds that username.",
  // Self-registration points at the tenant's default organization, so deleting
  // it would leave a new person nowhere to land.
  default_org: "This is the tenant's default organization and can't be deleted.",
  // The issuer names the primary host, so removing it would refuse every token
  // this tenant signed — including the one this console is holding.
  primary_domain: "This is the tenant's primary domain and can't be removed.",
  // The gateway derives the passkey RP ID from the request host, so a tenant that
  // answers on a second registrable domain holds passkeys that work on one host
  // and fail on the other. The add is refused instead.
  registrable_domain:
    "That host doesn't share the registrable domain (eTLD+1) of this tenant's existing domains. Passkeys would stop working, so the domain wasn't added.",
  // A revoke against a list the operator has been looking at for a while. The
  // person can remove their own passkey from the portal, and a second operator
  // can revoke it here, so the row on screen is simply stale — the device is
  // already out of service either way.
  passkey_not_found: "That passkey is already gone. Refresh to see what this account holds now.",
  invalid_input: "Some fields are invalid — check the form and try again.",
  internal_server_error: "The server hit an error. Please try again.",
  protected_claim: "That claim name is reserved (a protocol or trust claim) and can't be used.",
  scope_in_use: "This scope is still assigned to a client and can't be deleted.",
  // Rotate-secret answers both. Only a confidential OIDC client holds a secret,
  // so an application that carries no client, and a public client that
  // authenticates with PKCE, have nothing to rotate.
  no_client: "This application holds no OIDC client, so there is no secret to rotate.",
  public_client: "This is a public client. It authenticates with PKCE and holds no secret.",
  limit_exceeded: "Limit exceeded — too many mappers on this scope, or the value is too large.",
  send_failed: "The transport rejected the send — check the SMTP host, credentials, and TLS mode.",
  // Migration 00020 seeds the OIDC standard scopes. The provider resolves claims
  // through them, so a tenant cannot delete one — it can disable it.
  builtin_scope: "This is a built-in OIDC scope and can't be deleted. Disable it instead.",
  // The tenant default is the bottom level of the auth policy, so it has no
  // override to remove. Only an organization can be reset.
  tenant_scope: "The tenant default has nothing to inherit and can't be reset. Clear the fields you no longer set instead.",
  // Only an IAM_OWNER writes a tenant membership, so a tenant with none left could
  // never grant one again.
  last_owner: "The tenant must keep one IAM_OWNER — grant the role to somebody else first.",
  // A domain claim routes every person whose email carries it to the directory,
  // including the owners who hold a local password. One directory outage must
  // not lock every administrator out of the console, so the claim is refused.
  last_local_owner:
    "The tenant must keep one IAM_OWNER who signs in with a password this gateway holds. Give the role to such a person first.",
  // A domain routes every person whose email carries it to one directory, so two
  // providers cannot hold the same one. The identity-provider form names the
  // domain that is taken; this is the sentence every other surface reads.
  domain_already_claimed: "Another identity provider of this tenant already claims that domain.",
  // An identity provider stays at the level it was created at, so a tenant-wide
  // provider never becomes an organization's own.
  level_fixed: "An identity provider stays at the level it was created at.",
  // The connection test is an outbound call into a customer network, so it
  // carries a budget of its own.
  rate_limited: "Too many attempts. Wait a moment and try again.",
  // The budget lives only in Redis, and a budget nobody can read refuses the
  // test rather than letting an unmetered outbound call through.
  test_unavailable: "The connection test can't run at the moment. Try again shortly.",
};

/** Maps the gateway's resource-write error codes to a human sentence. */
export function mutationMessage(e: unknown): string {
  if (e instanceof MutationError) return MUTATION_MESSAGES[e.code] ?? `Request failed (${e.code}).`;
  if (e instanceof UnauthorizedError) return "Your session expired — sign in again.";
  return "Something went wrong.";
}

/** Renders a non-ok collection status as a title + reason. `role` names the role
 * a 403 needs, so a permission failure explains itself instead of showing empty.
 * `orgRole` names a second role that grants the same access within one
 * organization — notifications and auth policy are both manageable by an
 * ORG_OWNER inside their own org, and a sentence naming only the tenant-wide
 * role tells that operator they are locked out when they are not. */
export function describeStatus(
  s: CollectionStatus,
  resource: string,
  role?: string,
  orgRole?: string
): { title: string; body: string } | null {
  switch (s.state) {
    case "ok":
      return null;
    case "forbidden":
      return {
        title: `You can't view ${resource}.`,
        body: role
          ? `Reading ${resource} requires the ${role} role${orgRole ? `, or ${orgRole} for a specific organization` : ""}.`
          : MUTATION_MESSAGES.forbidden_read,
      };
    case "missing":
      return { title: `${resource} is unavailable.`, body: "This subsystem isn't configured on this deployment." };
    case "error":
      return { title: `Couldn't load ${resource}.`, body: s.message };
  }
}

// ── Write-authorization helpers (mirror the gateway's in-service role gate) ────
// UI gating only — the gateway re-checks every write server-side, so these decide
// what to *show*, not what is *allowed*.

/** IAM_OWNER/IAM_ADMIN — tenant-wide write authority. */
export function canManageTenant(me: Me): boolean {
  return me.tenantRoles.includes("IAM_OWNER") || me.tenantRoles.includes("IAM_ADMIN");
}

/** IAM_OWNER — required to manage tenant memberships. */
export function isIAMOwner(me: Me): boolean {
  return me.tenantRoles.includes("IAM_OWNER");
}

/** Tenant managers, or a caller holding one of `roles` in `orgId`. */
export function canWriteOrg(me: Me, orgId: string, roles: string[]): boolean {
  if (canManageTenant(me)) return true;
  return me.orgMemberships.some((om) => om.orgId === orgId && om.roles.some((r) => roles.includes(r)));
}

/** The org roles `me` may actually confer in `orgId` (mirrors
 * `Scope.AuthorizeOrgRoleGrant`): ORG_OWNER is the one elevated role, and only
 * a tenant manager or a sitting ORG_OWNER may hand it out — otherwise an
 * ORG_USER_MANAGER could mint an owner. Offering it anyway just buys a 403. */
export function grantableOrgRoles(me: Me, orgId: string, roles: string[]): string[] {
  if (canWriteOrg(me, orgId, ["ORG_OWNER"])) return roles;
  return roles.filter((r) => r !== "ORG_OWNER");
}

/** True when the caller can write to at least one org (gates create buttons). */
export function canWriteAnyOrg(me: Me, roles: string[]): boolean {
  if (canManageTenant(me)) return true;
  return me.orgMemberships.some((om) => om.roles.some((r) => roles.includes(r)));
}

// tmplBase is the templates path for a scope: an empty orgId is the tenant
// default (the tenant route); a real org id is that org's override route.
const tmplBase = (orgId?: string) =>
  orgId
    ? `/api/admin/orgs/${encodeURIComponent(orgId)}/notifications/templates`
    : `/api/admin/notifications/templates`;

/** Client for the notification-management admin API, proxied through the BFF.
 * Template methods take an optional orgId to target an organization's override;
 * omitted/empty targets the tenant default. */
export const notificationsApi = {
  // Same reason as `authPolicyApi.get`: the refusal is the answer.
  getSettings: () => getOptional<NotificationSettings>("/api/admin/notifications/settings"),
  updateSettings: (b: NotificationSettingsBody) =>
    mutate<NotificationSettings>("/api/admin/notifications/settings", "PATCH", b),
  sendTest: (to: string, template: string) =>
    mutate<{ ok: boolean }>("/api/admin/notifications/test", "POST", { to, template }),
  templates: (orgId?: string) => getJson<NotificationTemplateInfo[]>(tmplBase(orgId)),
  template: (key: string, orgId?: string) => getJson<NotificationTemplate>(`${tmplBase(orgId)}/${key}`),
  preview: (key: string, orgId?: string) => getJson<RenderedTemplate>(`${tmplBase(orgId)}/${key}/preview`),
  upsertTemplate: (key: string, b: NotificationTemplateBody, orgId?: string) =>
    mutate<NotificationTemplate>(`${tmplBase(orgId)}/${key}`, "PUT", b),
  deleteTemplate: (key: string, orgId?: string) =>
    mutate<{ ok: boolean }>(`${tmplBase(orgId)}/${key}`, "DELETE"),
};

// ── Identity providers (directory sign-in) ────────────────────────────────────

/** Transport of one directory. A boolean cannot tell StartTLS from LDAPS, and
 * those two differ in port and in handshake, so the wire value is an integer. */
export const IDP_MODE_PLAIN = 1;
export const IDP_MODE_STARTTLS = 2;
export const IDP_MODE_LDAPS = 3;

/** The scheme each transport accepts, mirroring `identityprovider.modeSchemes`.
 * The gateway is the enforcement point; this only marks the box before a save. */
export const IDP_MODE_SCHEMES: Record<number, string> = {
  [IDP_MODE_PLAIN]: "ldap://",
  [IDP_MODE_STARTTLS]: "ldap://",
  [IDP_MODE_LDAPS]: "ldaps://",
};

/** One directory as the console reads it.
 *
 * `bindPasswordSet` reports that a bind credential is stored. The credential is
 * write-only, and no read path answers it in any shape.
 *
 * `orgId` carries the level: "" is the tenant-wide provider, and a UUID is that
 * organization's own. A provider stays at the level it was created at. */
export interface IdentityProvider {
  id: string;
  tenantId: string;
  orgId: string;
  name: string;
  type: number;
  state: number; // 1 active, 2 inactive
  defaultOrgId: string;
  mode: number;
  servers: string[];
  rootCa: string;
  timeoutSeconds: number;
  bindDn: string;
  bindPasswordSet: boolean;
  baseDn: string;
  userObjectClasses: string[];
  userFilters: string[];
  userBase: string;
  attrId: string;
  attrUsername: string;
  attrEmail: string;
  attrFirstName: string;
  attrLastName: string;
  attrDisplayName: string;
  domains: string[];
  created: string;
}

/** Write body. The console submits the whole form, so every field except the
 * bind password replaces what is stored.
 *
 * `bindPassword` is the one write-only field, and it answers three ways: absent
 * keeps the stored credential, "" clears it, and a value replaces it.
 *
 * `confirmPlaintext` is the explicit confirmation a plain bind needs. The
 * gateway refuses mode 1 without it. */
export interface IdentityProviderBody {
  orgId?: string;
  name: string;
  state: number;
  defaultOrgId?: string;
  mode: number;
  confirmPlaintext: boolean;
  servers: string[];
  rootCa: string;
  timeoutSeconds: number;
  bindDn: string;
  bindPassword?: string;
  baseDn: string;
  userObjectClasses: string[];
  userFilters: string[];
  userBase: string;
  attrId: string;
  attrUsername: string;
  attrEmail: string;
  attrFirstName: string;
  attrLastName: string;
  attrDisplayName: string;
  domains: string[];
}

/** What one connection test answers.
 *
 * `stage` names the step that failed — "dial", "tls", "bind" or "search" — and
 * it is empty when every stage passed. `matched` is how many entries the search
 * matched, and it is read only when `ok` is true. A failed stage is a 200: the
 * test ran, so the console renders the stage rather than an error. */
export interface ConnectionTestResult {
  ok: boolean;
  stage: string;
  matched: number;
  detail: string;
}

const idpBase = "/api/admin/identity-providers";

/** Client for the identity-provider admin API, proxied through the BFF.
 *
 * The list is bounded — a tenant registers a handful of directories — so it
 * answers whole and it carries no pager.
 *
 * `test` without an id tests a configuration nobody saved yet, so an operator
 * checks a directory before the first save. */
export const identityProvidersApi = {
  // `getOptional`, not `getJson`: the read is tenant-manager only, and a 403 is
  // a permission answer the view has to say out loud.
  list: () => getOptional<IdentityProvider[]>(idpBase),
  create: (b: IdentityProviderBody) => mutate<IdentityProvider>(idpBase, "POST", b),
  update: (id: string, b: IdentityProviderBody) =>
    mutate<IdentityProvider>(`${idpBase}/${encodeURIComponent(id)}`, "PUT", b),
  remove: (id: string) => mutate<{ ok: boolean }>(`${idpBase}/${encodeURIComponent(id)}`, "DELETE"),
  test: (b: IdentityProviderBody, id?: string) =>
    mutate<ConnectionTestResult>(id ? `${idpBase}/${encodeURIComponent(id)}/test` : `${idpBase}/test`, "POST", b),
};
