"use client";

// Shared plumbing for the entity detail routes (/users/[id], /organizations/[id],
// /projects/[id], /applications/[id]).
//
// The record is read by id from the admin API, never re-derived from whatever the
// list route happened to have fetched — that is what makes a detail URL
// bookmarkable, survivable across a filter change, and correct once
// paginate-admin-list-api lands. `reload` re-reads the same id after a write.

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { notFound, usePathname, useRouter, useSearchParams } from "next/navigation";
import { UnauthorizedError, type Outcome } from "@/lib/console-api";
import { ViewNotice } from "./primitives";

/**
 * A detail view's open tab, held in `?tab=` rather than in component state.
 *
 * "Look at this user's sessions" is a place, so it needs an address: a tab in
 * `useState` cannot be pasted into a ticket, and Back walks out of the record
 * instead of back to the tab before it. An unknown or absent value falls to the
 * first tab, so a stale link still opens the record.
 */
export function useTabParam(tabs: string[]): [string, (t: string) => void] {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const raw = searchParams.get("tab");
  const active = tabs.find((t) => t === raw) ?? tabs[0];

  const set = useCallback(
    (t: string) => {
      const next = new URLSearchParams(searchParams.toString());
      if (t === tabs[0]) next.delete("tab");
      else next.set("tab", t);
      const qs = next.toString();
      router.push(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [router, pathname, searchParams, tabs]
  );

  return [active, set];
}

type RecordState<T> =
  | { phase: "loading" }
  | { phase: "ready"; record: T }
  | { phase: "absent" }
  | { phase: "error"; message: string };

export function useRecord<T>(fetcher: (id: string) => Promise<Outcome<T>>, id: string) {
  const [state, setState] = useState<RecordState<T>>({ phase: "loading" });

  // Written as a promise chain rather than async/await so every setState lands in
  // a continuation — nothing is set synchronously when the effect below runs it.
  const reload = useCallback((): Promise<void> => {
    return fetcher(id).then(
      // 403 and 404 both mean "not yours to see" here — the API already answers
      // 404 for a record outside the caller's scope, and leaking the difference
      // would confirm the id exists.
      (out) => setState(out.ok ? { phase: "ready", record: out.data } : { phase: "absent" }),
      (e: unknown) => {
        if (e instanceof UnauthorizedError) {
          window.location.href = "/auth/login";
          return;
        }
        setState({ phase: "error", message: e instanceof Error ? e.message : "Request failed" });
      }
    );
    // fetcher is a stable module-level function in every call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { state, reload };
}

/** Renders loading / not-found / error around a detail route's record. */
export function DetailRoute<T>({
  state,
  reload,
  resource,
  children,
}: {
  state: ReturnType<typeof useRecord<T>>["state"];
  reload: () => Promise<void>;
  resource: string;
  children: (record: T) => ReactNode;
}) {
  if (state.phase === "absent") notFound();
  if (state.phase === "loading") {
    return (
      <div className="fade-in" aria-busy="true">
        <div className="skel" style={{ width: 160, height: 14, marginBottom: 18 }} />
        <div className="skel" style={{ width: 320, height: 26, marginBottom: 24 }} />
        <div className="skel" style={{ width: "100%", height: 180, borderRadius: 14 }} />
      </div>
    );
  }
  if (state.phase === "error") {
    return (
      <ViewNotice title={`Couldn’t load this ${resource}.`} body={state.message} onRetry={() => void reload()} />
    );
  }
  return <>{children(state.record)}</>;
}

/** Back out of a detail/create route to its list. */
export function useBackTo(path: string) {
  const router = useRouter();
  return useCallback(() => router.push(path), [router, path]);
}
