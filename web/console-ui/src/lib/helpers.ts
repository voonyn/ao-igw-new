import type { OrgRef } from "./console-api";
import type { User } from "./types";

/**
 * Resolves an organization id to its name against the caller's accessible orgs
 * (`me.accessibleOrgs`), which the `/me` payload carries as (id, name) pairs.
 *
 * This is the one id→name lookup the console still does client-side, because the
 * set it looks in is bounded by the caller's memberships and already loaded. The
 * others — user, application, project — are joined onto the row server-side: a
 * view holding one page has no collection to search, and searching one per row
 * would be a request per row. Unknown ids fall back to the id, never to blank.
 */
export function orgName(orgs: OrgRef[], id: string | null): string {
  const o = orgs.find((x) => x.id === id);
  return o ? o.name : id || "—";
}

export function userDisplay(u: User | null | undefined): string {
  if (!u) return "—";
  return u.userType === 2 ? u.username : u.human?.displayName || u.username;
}

/** Renders a joined display name, falling back to the id it labels when the
 * referenced record is gone (the server sends an empty name, not an error). */
export function nameOr(name: string | undefined, id: string | null): string {
  return name || id || "—";
}

/** The console's unknown marker, for a field the gateway could not resolve for
 * THIS record — a session whose encrypted blob would not decode has no IP, and
 * a blank cell would report that as an empty IP rather than as "not known". */
export function orUnknown(v: string | null | undefined): string {
  return v || "—";
}

/** Distinct from `orUnknown`: an empty `lastAuth` is not a gap in what the
 * gateway knows, it is the positive fact that this user has never
 * authenticated. Saying "Never" states that; a dash would hide it. */
export function orNever(v: string | null | undefined): string {
  return v || "Never";
}

/**
 * THE timestamp rendering. Every surface goes through it, so none can drift.
 *
 * Local time **with the zone named**: a time rendered in the viewer's zone with
 * nothing saying so is two different times to two operators reading the same
 * audit event, and it silently disagreed with the raw UTC strings every other
 * screen used to print. Local-plus-zone is unambiguous and still correlates
 * with what the operator saw happen to them.
 *
 * An unparseable value is returned as-is rather than as "Invalid Date" — the
 * machine value is never worth hiding.
 */
export function fmtTs(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });
}

/** The exact value behind a rendered timestamp, for the `title`. Keeps the
 * machine string one hover away — an operator pasting an event into a ticket
 * needs it, and a shortened rendering must not be the only copy. */
export function utcTs(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString();
}

/** THE textarea-to-list reader. A form that collects a list of short values —
 * a password deny-list, the servers of a directory, the domains it claims —
 * gives the operator one box and splits it here, on a newline or a comma.
 * Blank entries are dropped, so a trailing newline never submits an empty value. */
export function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function initials(name: string): string {
  return (name || "?")
    .split(" ")
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

const AVATAR_HUES = [18, 152, 232, 282, 332, 62, 200];
export function avatarHue(name: string): number {
  let h = 0;
  for (let i = 0; i < (name || "").length; i++) h = (h * 31 + name.charCodeAt(i)) % 9973;
  return AVATAR_HUES[h % AVATAR_HUES.length];
}

/** Console page id <-> App Router path. */
export const PAGE_PATH: Record<string, string> = {
  overview: "/overview",
  orgs: "/organizations",
  projects: "/projects",
  apps: "/applications",
  users: "/users",
  members: "/members",
  provider: "/provider",
  scopes: "/scopes",
  notifications: "/notifications",
  keys: "/keys",
  sessions: "/sessions",
  tenants: "/tenants",
  bootstrap: "/bootstrap",
  groups: "/groups",
  roles: "/roles",
  policies: "/policies",
  federation: "/user-federation",
  audit: "/audit",
  catalog: "/catalog",
};

/**
 * THE name of a route. One table, three consumers: the sidebar nav item, the
 * breadcrumb, and the page `<h1>` (via `<PageHead>`). Nothing else may carry a
 * route's display string — three tables is how `/tenants` came to be called
 * "Tenant Settings", "Tenants", and "Tenants" on the same screen.
 */
export const PAGE_TITLES: Record<string, string> = {
  overview: "Overview",
  orgs: "Organizations",
  projects: "Projects",
  apps: "Applications",
  users: "Users",
  members: "Members & Roles",
  provider: "Provider Settings",
  scopes: "Scopes & Claims",
  notifications: "Notifications",
  keys: "Signing Keys",
  sessions: "Sessions",
  tenants: "Tenants",
  bootstrap: "Bootstrap",
  groups: "Groups",
  roles: "Custom Roles",
  policies: "Auth Policy",
  federation: "User Federation",
  audit: "Audit Log",
  catalog: "App Catalog",
};

/**
 * Resolves a pathname to its page id by LONGEST matching prefix.
 *
 * Exact matching is what made every route the detail and create pages added —
 * `/users/[id]`, `/users/new` — fall through to "Overview" in the breadcrumb.
 * Longest-prefix also keeps `/organizations` from being claimed by a shorter
 * entry that happens to be its prefix.
 */
export function pageIdFromPath(pathname: string): string {
  let best = "overview";
  let bestLen = 0;
  for (const [id, path] of Object.entries(PAGE_PATH)) {
    if (pathname !== path && !pathname.startsWith(path + "/")) continue;
    if (path.length > bestLen) {
      best = id;
      bestLen = path.length;
    }
  }
  return best;
}

export const PROTO_NOTES: Record<string, string> = {
  groups: "Groups are not part of the AlphaOmega schema yet — membership shown here is sample data and nothing is persisted.",
  roles: "Custom roles with permission matrices are a future capability. Today the schema only stores fixed IAM/ORG role lists on memberships (see Members & Roles).",
  catalog: "A curated app catalog (SCIM provisioning, SAML tiles) is a future capability layered on top of the applications table.",
};
