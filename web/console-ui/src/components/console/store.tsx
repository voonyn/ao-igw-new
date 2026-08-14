"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createInitialLegacy } from "@/lib/data-legacy";
import {
  describeStatus,
  getTotal,
  loadConsoleData,
  mutationMessage,
  UnauthorizedError,
  type CollectionKey,
  type CollectionStatus,
  type ListQuery,
  PICKER_PAGE,
  readPicker,
  type Me,
  type OrgRef,
  type PageReader,
} from "@/lib/console-api";
import { PAGE_PATH } from "@/lib/helpers";
import type { Bootstrap, Db, LegacyApp, LegacyGroup, LegacyRole, Page } from "@/lib/types";

/** A refusal must not render like a success — the host styles on this. */
export type ToastSeverity = "success" | "error" | "info";

export interface ToastItem {
  id: number;
  msg: string;
  icon?: string;
  severity: ToastSeverity;
}

// Writes go straight to the admin API and finish with `reload()`. There is
// deliberately no local-mutation action here: a control that can't reach the
// server has nothing to bind to, so it can't report a success that never happened.
export interface Actions {
  toast: (msg: string, icon?: string, severity?: ToastSeverity) => void;
  nav: (page: string) => void;
  /** Scopes the console to one accessible organization (null = all accessible).
   * The selector is passed to the API, never applied to a held page: filtering a
   * returned page would shrink it below the requested limit and misreport a
   * partial list as exhausted. */
  selectOrg: (orgId: string | null) => void;
  /** Re-fetches the shared state and re-runs every mounted paged list from page
   * one. Lists no longer live in this store, so a write invalidates them through
   * `dataVersion` rather than by refetching a collection nobody holds. */
  reload: () => Promise<void>;
}

interface LegacyState {
  roles: LegacyRole[];
  users: import("@/lib/types").LegacyUser[];
  apps: LegacyApp[];
  groups: LegacyGroup[];
}

interface LegacyActions {
  updateGroup: (id: string, patch: Partial<LegacyGroup>) => void;
  updateApp: (id: string, patch: Partial<LegacyApp>) => void;
  updateRolePerm: (roleId: string, res: string, action: string, grant: boolean) => void;
}

interface ConsoleContextValue {
  db: Db;
  tenantId: string;
  me: Me;
  bootstrap: Bootstrap | null;
  /** Per-collection load outcome — a view renders its own error from this
   * instead of the console blanking on one failed request. */
  status: Record<CollectionKey, CollectionStatus>;
  accessibleOrgs: OrgRef[];
  selectedOrgId: string | null;
  /** Bumped by every successful write. Paged lists depend on it, so a write
   * invalidates them without this store knowing what any view is showing. */
  dataVersion: number;
  A: Actions;
  legacy: LegacyState;
  legacyActions: LegacyActions;
  toasts: ToastItem[];
  theme: "light" | "dark";
  toggleTheme: () => void;
}

const ConsoleContext = createContext<ConsoleContextValue | null>(null);

// The client-side org narrowing that used to live here (`scopeDb`) is gone. It
// filtered a whole-tenant store down to one organization's subtree, which was
// only ever correct because the store held every row; against a page it would
// have returned fewer rows than the caller asked for and reported the list
// exhausted. Narrowing is now a query predicate — every paged read passes
// `orgId` and the server applies it (AZ-4 closed server-side).

export function ConsoleProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [db, setDb] = useState<Db | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [collections, setCollections] = useState<Record<CollectionKey, CollectionStatus> | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [dataVersion, setDataVersion] = useState(0);
  const [legacy, setLegacy] = useState<LegacyState>(createInitialLegacy);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const toastId = useRef(0);

  const toast = useCallback((msg: string, icon?: string, severity?: ToastSeverity) => {
    const id = ++toastId.current;
    // Failure toasts have always carried the "alert" icon, so that stays the
    // default signal; `severity` is for the cases where it isn't enough.
    const sev: ToastSeverity = severity ?? (icon === "alert" ? "error" : "success");
    setToasts((ts) => ts.concat([{ id, msg, icon, severity: sev }]));
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), 3200);
  }, []);

  // Load live data once on mount. A 401 means the session is gone — bounce to login.
  useEffect(() => {
    let cancelled = false;
    loadConsoleData()
      .then((data) => {
        if (cancelled) return;
        setDb(data.db);
        setMe(data.me);
        setBootstrap(data.bootstrap);
        setCollections(data.status);
        setStatus("ready");
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof UnauthorizedError) {
          window.location.href = "/auth/login";
          return;
        }
        console.error("console: failed to load admin data", err);
        setStatus("error");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // ponytail: writes re-read the shared state and restart every mounted paged
  // list from page one rather than patching local state — simplest correct
  // refresh at admin scale, and the only one that cannot show a stale row. It
  // does discard the pages a view had already loaded; make it incremental if
  // anyone is ever deep in a list when they write.
  const reload = useCallback(async () => {
    const data = await loadConsoleData();
    setDb(data.db);
    setMe(data.me);
    setBootstrap(data.bootstrap);
    setCollections(data.status);
    setDataVersion((v) => v + 1);
  }, []);

  const A = useMemo<Actions>(
    () => ({
      toast,
      nav: (page) => {
        const path = PAGE_PATH[page];
        if (path) router.push(path);
      },
      selectOrg: (orgId) => setSelectedOrgId(orgId),
      reload,
    }),
    [router, toast, reload]
  );

  const legacyActions = useMemo<LegacyActions>(
    () => ({
      updateGroup: (id, patch) =>
        setLegacy((l) => ({ ...l, groups: l.groups.map((g) => (g.id === id ? { ...g, ...patch } : g)) })),
      updateApp: (id, patch) =>
        setLegacy((l) => ({ ...l, apps: l.apps.map((a) => (a.id === id ? { ...a, ...patch } : a)) })),
      updateRolePerm: (roleId, res, action, grant) =>
        setLegacy((l) => ({
          ...l,
          roles: l.roles.map((r) => {
            if (r.id !== roleId) return r;
            const perms = { ...r.perms };
            const list = (perms[res] || []).slice();
            const i = list.indexOf(action);
            if (grant && i === -1) list.push(action);
            if (!grant && i !== -1) list.splice(i, 1);
            perms[res] = list;
            return { ...r, perms };
          }),
        })),
    }),
    []
  );

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === "dark" ? "light" : "dark";
      if (typeof document !== "undefined") {
        document.documentElement.setAttribute("data-theme", next);
        try {
          localStorage.setItem("ao-console-theme", next);
        } catch {
          /* ignore */
        }
      }
      return next;
    });
  }, []);

  // Sync icon state with the attribute the no-flash script already applied.
  useEffect(() => {
    const current = document.documentElement.getAttribute("data-theme");
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (current === "dark" || current === "light") setTheme(current);
  }, []);

  const value = useMemo<ConsoleContextValue>(() => {
    if (!db || !me || !collections) return null as unknown as ConsoleContextValue;
    return {
      db,
      tenantId: me.tenant.id,
      me,
      bootstrap,
      status: collections,
      accessibleOrgs: me.accessibleOrgs,
      selectedOrgId,
      dataVersion,
      A,
      legacy,
      legacyActions,
      toasts,
      theme,
      toggleTheme,
    };
  }, [db, me, bootstrap, collections, selectedOrgId, dataVersion, A, legacy, legacyActions, toasts, theme, toggleTheme]);

  if (status === "loading" || !db || !me || !collections) return <Splash label="Loading console…" />;
  if (status === "error") return <Splash label="Couldn't load the console. Check the admin API and reload." error />;

  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>;
}

function Splash({ label, error }: { label: string; error?: boolean }) {
  return (
    <div
      style={{
        minHeight: "100dvh",
        display: "grid",
        placeItems: "center",
        padding: "2rem",
        textAlign: "center",
        color: error ? "var(--danger, #c0392b)" : "var(--muted, #6b7280)",
        fontFamily: "var(--font-inter, system-ui), sans-serif",
        fontSize: 14,
      }}
    >
      {label}
    </div>
  );
}

export function useConsole(): ConsoleContextValue {
  const ctx = useContext(ConsoleContext);
  if (!ctx) throw new Error("useConsole must be used within ConsoleProvider");
  return ctx;
}

/** Options for one guarded mutation. `after` replaces the default console
 * refetch for views that own their own list (scopes, notifications, audit). */
export interface RunOpts {
  ok?: string;
  icon?: string;
  after?: () => Promise<unknown> | unknown;
}

/**
 * Guards a mutation: holds a pending flag for its duration, toasts the outcome
 * with the one message the error code maps to, then refetches. Resolves `true`
 * only when the write succeeded, so a caller can close a page on success.
 *
 * ponytail: one flag per component, not per control — every mutating control in
 * a view goes disabled while any one of them is in flight. That is what makes
 * double-submit impossible without threading a pending key through every row;
 * key it per row only if a view ever needs two writes running at once.
 */
export function usePending(): [boolean, (fn: () => Promise<unknown>, opts?: RunOpts) => Promise<boolean>] {
  const { A } = useConsole();
  const [pending, setPending] = useState(false);
  const run = useCallback(
    async (fn: () => Promise<unknown>, opts: RunOpts = {}) => {
      setPending(true);
      try {
        await fn();
        if (opts.ok) A.toast(opts.ok, opts.icon);
        if (opts.after) await opts.after();
        else await A.reload();
        return true;
      } catch (e) {
        A.toast(mutationMessage(e), "alert", "error");
        return false;
      } finally {
        setPending(false);
      }
    },
    [A]
  );
  return [pending, run];
}

// ── Paged lists ──────────────────────────────────────────────────────────────

/** One view's page state. `total` is the server's count of the whole scoped list
 * (not of what has been loaded), and is null until the first page answers or
 * when the list has no count to give. */
export interface PagedList<P extends Page<unknown>> {
  items: P["items"];
  /** The whole first-page body, for a response that carries more than `items`
   * (only `/members` does: it answers two collections, and the cursor describes
   * one of them). Null until the first page lands. */
  raw: P | null;
  total: number | null;
  /** True while more rows remain — i.e. the last page carried a cursor. */
  hasMore: boolean;
  /** The first page is in flight; the table has nothing to show yet. */
  loading: boolean;
  /** A *Load more* is in flight; the rows already shown stay shown. */
  loadingMore: boolean;
  /** Non-null when the list could not be read, phrased for the operator. */
  error: { title: string; body: string } | null;
  /** Picker mode only: the collection was longer than PICKER_MAX_PAGES pages, so
   * rows are missing from `items`. A short `<select>` that does not say this is
   * indistinguishable from a complete one. */
  truncated: boolean;
  /** The page size in effect — what the next fetch will send as `limit`. */
  pageSize: number;
  /** Switches page size: discards the rows already loaded and refetches from the
   * head, so the table never mixes sizes or shows a total from a superseded page. */
  setPageSize: (n: number) => void;
  /** The narrowing in effect — sort key, direction, search term, typed filters.
   * These are REQUEST parameters: they reach the query, so a match on page four
   * is found and `total` describes what the table shows. */
  query: ListQuery;
  /** Merges a partial narrowing and refetches from the head. An empty string or
   * `undefined` clears a key rather than sending it empty. */
  setQuery: (patch: ListQuery) => void;
  /** Walks the collection under the ACTIVE query to the picker bound and returns
   * every row it retrieved. `truncated` means the bound cut the walk short — an
   * export built from it is partial and has to say so. */
  readAll: () => Promise<{ rows: P["items"]; truncated: boolean }>;
  loadMore: () => void;
  reload: () => void;
}

const PAGE_SIZE = 50;

/** Per-list overrides. `role` names the role a 403 needs, so a permission failure
 * explains itself. `limit` sets the initial page size for a table (the selector
 * moves it afterwards) and the fixed size for a picker. */
export interface PagedOpts {
  role?: string;
  limit?: number;
  /** Picker mode: the first read follows `nextCursor` to exhaustion, bounded by
   * PICKER_MAX_PAGES, because a `<select>` has no *Load more*. `truncated` on the
   * result reports whether the bound cut the collection short. */
  picker?: boolean;
  /** Overrides the console's org selector for this list. A detail page that
   * lists a child collection knows its own organization and should narrow to it
   * regardless of what the global switcher says. */
  orgId?: string | null;
  /** Narrows the read to one subject, for the lists that have one (sessions,
   * grants). Fixed by the view — a user's Sessions tab is about that user — so
   * it is an option rather than part of the operator-editable `query`. */
  userId?: string;
  /** Mirrors the narrowing into the URL, so a filtered table can be bookmarked,
   * pasted into a ticket, and reopened as itself. At most ONE list per route may
   * claim it; a detail tab's inner table keeps its state local (the route's own
   * `?tab=` is what makes that addressable). */
  urlSync?: boolean;
}

// ── Query state ──────────────────────────────────────────────────────────────

/** The narrowing plus the page size — everything a shared link has to carry. */
interface QueryState extends ListQuery {
  limit: number;
}

// clean drops the keys that mean "no opinion", so an absent filter is absent
// from the request rather than sent empty for the server to interpret.
function clean(q: QueryState): QueryState {
  const out: QueryState = { limit: q.limit };
  if (q.sort) out.sort = q.sort;
  if (q.dir) out.dir = q.dir;
  if (q.q) out.q = q.q;
  if (q.state !== undefined) out.state = q.state;
  if (q.type !== undefined) out.type = q.type;
  return out;
}

// fromParams reads the narrowing back out of a URL. A malformed integer is
// dropped rather than forwarded: it could not have been produced by a control,
// and sending it would 422 a table an operator only wanted to bookmark.
function fromParams(sp: URLSearchParams, limit: number): QueryState {
  const num = (k: string) => {
    const v = sp.get(k);
    if (!v) return undefined;
    const n = Number(v);
    return Number.isInteger(n) ? n : undefined;
  };
  const dir = sp.get("dir");
  return clean({
    limit: num("limit") ?? limit,
    sort: sp.get("sort") ?? undefined,
    dir: dir === "asc" || dir === "desc" ? dir : undefined,
    q: sp.get("q") ?? undefined,
    state: num("state"),
    type: num("type"),
  });
}

// toParams writes the narrowing over whatever else the URL carries (`?tab=`,
// say), so syncing a table cannot drop another control's parameter.
function toParams(sp: URLSearchParams, q: QueryState, defaultLimit: number): string {
  const next = new URLSearchParams(sp.toString());
  const put = (k: string, v: string | undefined) => (v ? next.set(k, v) : next.delete(k));
  put("sort", q.sort);
  put("dir", q.dir);
  put("q", q.q);
  put("state", q.state === undefined ? undefined : String(q.state));
  put("type", q.type === undefined ? undefined : String(q.type));
  put("limit", q.limit === defaultLimit ? undefined : String(q.limit));
  return next.toString();
}

/**
 * Holds one table's narrowing, either in the URL or in local state.
 *
 * URL-backed is the default for a list view because that is what makes a
 * narrowed table shareable, and it comes with Back for free: each change is a
 * history entry, so returning to the previous narrowing is the browser's job
 * rather than ours. The search box debounces before it lands here, so a typed
 * word is one entry and not one per keystroke.
 */
function useQueryState(urlSync: boolean, defaultLimit: number): [QueryState, (patch: Partial<QueryState>) => void] {
  const router = useRouter();
  const pathname = usePathname();
  // Called unconditionally — hooks may not be conditional — and read only when
  // this list owns the URL.
  const searchParams = useSearchParams();
  const [local, setLocal] = useState<QueryState>({ limit: defaultLimit });

  const fromUrl = useMemo(() => fromParams(new URLSearchParams(searchParams.toString()), defaultLimit), [searchParams, defaultLimit]);
  const state = urlSync ? fromUrl : local;

  const set = useCallback(
    (patch: Partial<QueryState>) => {
      const next = clean({ ...state, ...patch });
      if (!urlSync) {
        setLocal(next);
        return;
      }
      const qs = toParams(new URLSearchParams(searchParams.toString()), next, defaultLimit);
      router.push(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [state, urlSync, searchParams, router, pathname, defaultLimit]
  );

  return [state, set];
}

/**
 * Drives one paged list: first page on mount, *Load more* appends, and a fresh
 * page one whenever the organization selector moves or a write lands.
 *
 * `read` must be a stable reference (the `pages.*` consts are); it is a
 * dependency, so an inline arrow would refetch on every render.
 *
 * The selector is a fetch parameter, never a filter over `items`. Narrowing a
 * page client-side returns fewer rows than were asked for, which reads as
 * "end of list" — the exact failure paging exists to remove.
 */
export function usePagedList<P extends Page<unknown>>(read: PageReader<P>, resource: string, opts: PagedOpts = {}): PagedList<P> {
  const { role, picker = false, userId, urlSync = false } = opts;
  const { selectedOrgId, dataVersion } = useConsole();
  const orgId = opts.orgId !== undefined ? opts.orgId : selectedOrgId;
  // The narrowing and the size travel together: both restart the list from the
  // head (D7), and both belong in a shared link.
  const [state, setState] = useQueryState(urlSync, picker ? PICKER_PAGE : (opts.limit ?? PAGE_SIZE));
  const { limit, ...query } = state;
  const [items, setItems] = useState<P["items"]>([]);
  const [raw, setRaw] = useState<P | null>(null);
  const [total, setTotal] = useState<number | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<{ title: string; body: string } | null>(null);
  const [nonce, setNonce] = useState(0);

  // Spread into the deps rather than the object itself: `query` is rebuilt every
  // render, so depending on it would refetch continuously.
  const { sort, dir, q, state: stateFilter, type } = query;
  const scope = useMemo(
    () => ({ orgId, userId, sort, dir, q, state: stateFilter, type }),
    [orgId, userId, sort, dir, q, stateFilter, type]
  );

  useEffect(() => {
    let cancelled = false;
    // The pending flag has to flip before the request is issued — it IS the
    // synchronization with the external system, not a render derived from one.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(true);
    (picker ? readPicker(read, scope) : read({ ...scope, limit }))
      .then((out) => {
        if (cancelled) return;
        if (!out.ok) {
          setItems([]);
          setRaw(null);
          setTotal(null);
          setCursor(undefined);
          setError(describeStatus({ state: out.reason }, resource, role));
          return;
        }
        setItems(out.data.items ?? []);
        setRaw(out.data);
        setTotal(out.data.total ?? null);
        setCursor(out.data.nextCursor);
        setError(null);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof UnauthorizedError) {
          window.location.href = "/auth/login";
          return;
        }
        setItems([]);
        setRaw(null);
        setTotal(null);
        setCursor(undefined);
        setError(describeStatus({ state: "error", message: e instanceof Error ? e.message : String(e) }, resource));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [read, resource, role, limit, picker, scope, dataVersion, nonce]);

  const loadMore = useCallback(() => {
    if (!cursor || loadingMore) return;
    setLoadingMore(true);
    read({ ...scope, limit, cursor })
      .then((out) => {
        // A page that 403s mid-scroll means the role changed under the caller;
        // stop rather than silently ending the list on a permission error.
        if (!out.ok) {
          setError(describeStatus({ state: out.reason }, resource, role));
          return;
        }
        setItems((prev) => prev.concat(out.data.items ?? []));
        setCursor(out.data.nextCursor);
      })
      .catch((e: unknown) => {
        if (e instanceof UnauthorizedError) {
          window.location.href = "/auth/login";
          return;
        }
        setError(describeStatus({ state: "error", message: e instanceof Error ? e.message : String(e) }, resource));
      })
      .finally(() => setLoadingMore(false));
  }, [read, cursor, loadingMore, limit, scope, resource, role]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  // Switching size or narrowing discards the accumulated rows and refetches page
  // one with no cursor: the rows already shown were fetched under the old query,
  // so keeping them would leave the table a mix of scopes with a total from a
  // superseded page. A cursor is only valid in the ordering it was minted in —
  // the gateway refuses it in another — so dropping it is required, not tidiness.
  const restart = useCallback(() => {
    setItems([]);
    setRaw(null);
    setTotal(null);
    setCursor(undefined);
  }, []);

  const setPageSize = useCallback(
    (n: number) => {
      if (n === limit) return;
      restart();
      setState({ limit: n });
    },
    [limit, restart, setState]
  );

  const setQuery = useCallback(
    (patch: ListQuery) => {
      restart();
      setState(patch);
    },
    [restart, setState]
  );

  // The export walk. Same reader, same narrowing, same bound as a picker — an
  // export is a picker that writes a file instead of filling a <select>.
  const readAll = useCallback(async () => {
    const out = await readPicker(read, scope);
    if (!out.ok) throw new Error(out.reason);
    return { rows: (out.data.items ?? []) as P["items"], truncated: Boolean(out.data.nextCursor) };
  }, [read, scope]);

  return {
    items,
    raw,
    total,
    hasMore: Boolean(cursor),
    loading,
    loadingMore,
    error,
    truncated: picker && Boolean(cursor),
    pageSize: limit,
    setPageSize,
    query,
    setQuery,
    readAll,
    loadMore,
    reload,
  };
}

/**
 * Sidebar badge counts, read as scoped totals rather than by measuring a held
 * collection — no view holds one any more.
 *
 * These count what the corresponding list contains, which is a small change from
 * the old badges: those excluded soft-deleted rows and counted only active
 * sessions, so a badge could disagree with the list beside it. `keys` and
 * `tenants` stay local because both are bounded reads the store still holds.
 */
export function useCounts() {
  const { db, tenantId, selectedOrgId, dataVersion } = useConsole();
  const [totals, setTotals] = useState({ orgs: 0, projects: 0, apps: 0, users: 0, sessions: 0 });

  useEffect(() => {
    let cancelled = false;
    const opts = { orgId: selectedOrgId };
    Promise.all([
      getTotal("/api/admin/organizations", opts),
      getTotal("/api/admin/projects", opts),
      getTotal("/api/admin/applications", opts),
      getTotal("/api/admin/users", opts),
      getTotal("/api/admin/sessions", opts),
    ])
      .then(([orgs, projects, apps, users, sessions]) => {
        if (!cancelled) setTotals({ orgs, projects, apps, users, sessions });
      })
      // A badge is decoration: a failed count must not take the sidebar with it.
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [selectedOrgId, dataVersion]);

  return useMemo(
    () => ({
      ...totals,
      keys: db.keys.filter((k) => k.tenantId === tenantId && k.state === 1).length,
      tenants: db.tenants.filter((x) => x.state !== 3).length,
    }),
    [totals, db, tenantId]
  );
}
