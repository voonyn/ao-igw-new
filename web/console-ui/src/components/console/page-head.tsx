"use client";

// The page heading and the breadcrumb's trailing segment — both fed from
// `PAGE_TITLES`, the one table that names a route (lib/helpers.ts).

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { PAGE_TITLES } from "@/lib/helpers";

/**
 * The record a detail route is showing, contributed to the breadcrumb.
 *
 * A separate context rather than a field on `ConsoleContext`: it changes on
 * every navigation, and putting it there would re-render every consumer of the
 * console store — sidebar counts included — to relabel one breadcrumb segment.
 */
const CrumbTail = createContext<{ tail: string | null; setTail: (v: string | null) => void }>({
  tail: null,
  setTail: () => {},
});

export function CrumbProvider({ children }: { children: ReactNode }) {
  const [tail, setTail] = useState<string | null>(null);
  return <CrumbTail.Provider value={{ tail, setTail }}>{children}</CrumbTail.Provider>;
}

/** Read by the topbar. */
export function useCrumbTail(): string | null {
  return useContext(CrumbTail).tail;
}

/**
 * Names the record this route is showing. Cleared on unmount, so navigating out
 * of a detail route cannot leave its name hanging on the list's breadcrumb.
 */
export function useSetCrumbTail(name: string | null | undefined) {
  const { setTail } = useContext(CrumbTail);
  useEffect(() => {
    setTail(name ?? null);
    return () => setTail(null);
  }, [name, setTail]);
}

/**
 * A list view's header. The `<h1>` is read from `PAGE_TITLES` by page id — a
 * view no longer holds a heading string that can disagree with the navigation
 * item and the breadcrumb pointing at it.
 */
export function PageHead({ page, sub, actions }: { page: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{PAGE_TITLES[page] ?? page}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}
