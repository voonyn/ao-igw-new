"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import { Icon } from "./icons";
import { Menu } from "./overlays";
import { Btn, Cbx, confirmAction, LoadMore, PageCount, PageSize, SearchBox, ViewNotice, type ConfirmOptions } from "./primitives";
import { useConsole, type PagedList } from "./store";
import { mutationMessage } from "@/lib/console-api";
import { csvCell, downloadCsv } from "@/lib/csv";
import type { Page } from "@/lib/types";

/**
 * One column of a console table.
 *
 * `header` is a plain string rather than a node because it has three jobs: the
 * visible label, the column chooser's entry, and the CSV header. A node would
 * serve the first and silently fail the other two.
 */
export interface Column<T> {
  /** Stable id. It keys the column-visibility preference, so renaming it resets
   * that operator's choice — pick it once. */
  key: string;
  header: string;
  cell: (row: T) => ReactNode;
  /** A key from this list's server-side sort allowlist. Absent means the column
   * is NOT sortable, and it renders as text rather than as a dead control. */
  sort?: string;
  /** Which way the first click sorts. Defaults to ascending; a timestamp column
   * usually wants `desc`, because "most recent first" is what is being asked. */
  defaultDir?: "asc" | "desc";
  /** Extra class for both the `th` and the `td` (`hide-md`, `mono`, …). */
  className?: string;
  /** Excluded from the column chooser — the identity column a table would be
   * unreadable without, and the trailing actions column. */
  fixed?: boolean;
  /** The column's value as text, for the CSV export. A column without one is
   * omitted from the file rather than exported as an empty string. */
  text?: (row: T) => string;
}

/**
 * A bulk action: the SAME per-object write the single-row control calls, issued
 * once per selected row.
 *
 * There is no batch endpoint behind this by design. Reusing the existing write
 * means authorization, auditing, and error mapping are unchanged by
 * construction, and a partial failure is naturally expressible — which is why
 * the result is reported per row rather than as one toast.
 */
export interface BulkAction<T> {
  label: string;
  icon?: string;
  destructive?: boolean;
  /** One confirmation, naming the count and the consequence. */
  confirm: (n: number) => ConfirmOptions;
  run: (row: T) => Promise<unknown>;
  /** Rows the action cannot apply to. They stay selectable but are skipped, and
   * the confirmation counts only what will actually be written. */
  applies?: (row: T) => boolean;
  /** Names a row in the confirmation and the failure list. */
  describe?: (row: T) => string;
}

export interface DataTableProps<T> {
  /** Identifies this table's column preference in `localStorage`. */
  id: string;
  list: PagedList<Page<T>>;
  columns: Column<T>[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  /** Singular noun for the count badge ("user" → "12 users"). */
  noun: string;
  /** The empty state, phrased IN SCOPE. Never "on the pages loaded so far" —
   * the narrowing reaches the query now, so an empty result means the collection
   * is empty under it. */
  empty: string;
  /** Renders the search box. `fields` names what the server actually matches,
   * because a search that silently ignores a field is worse than no search. */
  search?: { fields: string; placeholder?: string };
  /** View-supplied filter controls, rendered between search and the counts. */
  filters?: ReactNode;
  /** Extra controls at the right of the toolbar (a *New …* button belongs in
   * the page head, not here). */
  toolbar?: ReactNode;
  /** Enables row selection and the bulk bar. */
  bulk?: BulkAction<T>[];
  /** Enables *Export CSV*, writing `<name>.csv`. */
  exportName?: string;
  /** Lets a row-level popover (a menu anchored inside a cell) escape the card.
   * The card clips by default so the table's first and last rows stay inside its
   * rounded corners; a table whose cells open menus has to trade that away. */
  overflowVisible?: boolean;
}

/**
 * Makes a clickable `<tr>` reachable and activatable from the keyboard.
 *
 * Spread onto the row. It adds a tab stop and Enter/Space; it deliberately does
 * NOT set `role="button"`, which would take the row out of the table's grid and
 * cost every cell its column-header association — the console needs both, and
 * only one of them can be expressed on the `tr` itself.
 *
 * `.clickable` is what earns the pointer cursor, so the three tables whose rows
 * do not navigate (keys, members, roles) stop claiming they do.
 */
export function rowActivation(onActivate: () => void) {
  return {
    className: "clickable",
    tabIndex: 0,
    onClick: onActivate,
    onKeyDown: (e: ReactKeyboardEvent<HTMLTableRowElement>) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      // Space would scroll the page; Enter would submit an enclosing form.
      e.preventDefault();
      onActivate();
    },
  };
}

/** How many bulk writes run at once. A selection of 100 must not open 100
 * connections; four keeps the run visibly progressing without flooding the
 * gateway. */
const BULK_CONCURRENCY = 4;

const colPrefKey = (id: string) => `ao-console-cols:${id}`;

// readHidden restores the operator's hidden-column set. It is per-operator
// preference, NOT table state, which is why it lives here and not in the URL: a
// shared link must not impose the sender's layout on the recipient.
function readHidden(id: string): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(colPrefKey(id));
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((k): k is string => typeof k === "string") : [];
  } catch {
    return [];
  }
}

export function DataTable<T>({
  id,
  list,
  columns,
  rowKey,
  onRowClick,
  noun,
  empty,
  search,
  filters,
  toolbar,
  bulk,
  exportName,
  overflowVisible,
}: DataTableProps<T>) {
  const { A } = useConsole();
  const [hidden, setHidden] = useState<string[]>([]);
  const [chooser, setChooser] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [progress, setProgress] = useState<{ done: number; total: number; label: string } | null>(null);
  const [failures, setFailures] = useState<{ who: string; why: string }[]>([]);
  const [exporting, setExporting] = useState(false);
  const [exportNote, setExportNote] = useState<string | null>(null);

  // Read the preference after mount: localStorage does not exist on the server,
  // and seeding state from it during render would hydrate mismatched.
  //
  // `id` changing means this is now a DIFFERENT table — a view that swaps tables
  // in one position (Sessions/Grants, the two Members tabs) reuses this component
  // rather than remounting it, so the selection has to be dropped with the
  // preference or rows stay selected under keys the new table does not have.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHidden(readHidden(id));
    setSelected([]);
  }, [id]);

  const toggleColumn = useCallback(
    (key: string) => {
      setHidden((prev) => {
        const next = prev.includes(key) ? prev.filter((k) => k !== key) : prev.concat([key]);
        try {
          window.localStorage.setItem(colPrefKey(id), JSON.stringify(next));
        } catch {
          /* a table that cannot persist its layout still renders */
        }
        return next;
      });
    },
    [id]
  );

  const shown = useMemo(() => columns.filter((c) => c.fixed || !hidden.includes(c.key)), [columns, hidden]);
  const rows = list.items as T[];
  const { sort, dir } = list.query;

  const onSort = useCallback(
    (col: Column<T>) => {
      if (!col.sort) return;
      const active = sort === col.sort;
      const next = active ? (dir === "asc" ? "desc" : "asc") : (col.defaultDir ?? "asc");
      list.setQuery({ sort: col.sort, dir: next });
    },
    [list, sort, dir]
  );

  // ── Selection ──────────────────────────────────────────────────────────────

  const keys = useMemo(() => rows.map(rowKey), [rows, rowKey]);
  const allSelected = keys.length > 0 && keys.every((k) => selected.includes(k));
  const selectedRows = useMemo(() => rows.filter((r) => selected.includes(rowKey(r))), [rows, selected, rowKey]);

  const toggleRow = useCallback((key: string) => {
    setSelected((prev) => (prev.includes(key) ? prev.filter((k) => k !== key) : prev.concat([key])));
  }, []);

  async function runBulk(action: BulkAction<T>) {
    const targets = action.applies ? selectedRows.filter(action.applies) : selectedRows;
    if (targets.length === 0) {
      A.toast(`No selected ${noun}s that ${action.label.toLowerCase()} applies to`, "alert", "error");
      return;
    }
    if (!(await confirmAction(action.confirm(targets.length)))) return;

    const name = (r: T) => action.describe?.(r) ?? rowKey(r);
    const failed: { row: T; why: string }[] = [];
    let done = 0;
    setFailures([]);
    setProgress({ done: 0, total: targets.length, label: action.label });

    // ponytail: a fixed-size worker pool over one shared index — the smallest
    // thing that bounds concurrency without a queue library. Each write is the
    // one the single-row control already issues, so nothing here needs to know
    // what the action does.
    const queue = targets.slice();
    await Promise.all(
      Array.from({ length: Math.min(BULK_CONCURRENCY, queue.length) }, async () => {
        for (let row = queue.shift(); row !== undefined; row = queue.shift()) {
          try {
            await action.run(row);
          } catch (e) {
            failed.push({ row, why: mutationMessage(e) });
          }
          done += 1;
          setProgress({ done, total: targets.length, label: action.label });
        }
      })
    );

    setProgress(null);
    if (failed.length === 0) {
      // Cleared only on a clean run. A partial run keeps the failures selected
      // so the retry is the same two clicks as the first attempt.
      setSelected([]);
      A.toast(`${action.label}: ${targets.length} ${targets.length === 1 ? noun : noun + "s"}`, action.icon);
    } else {
      setSelected(failed.map((f) => rowKey(f.row)));
      setFailures(failed.map((f) => ({ who: name(f.row), why: f.why })));
    }
    await A.reload();
  }

  // ── Export ─────────────────────────────────────────────────────────────────

  async function exportCsv() {
    if (!exportName) return;
    const cols = shown.filter((c) => c.text);
    if (cols.length === 0) return;
    setExporting(true);
    setExportNote(null);
    try {
      const { rows: all, truncated } = await list.readAll();
      const lines = [cols.map((c) => csvCell(c.header)).join(",")];
      for (const r of all as T[]) lines.push(cols.map((c) => csvCell(c.text!(r))).join(","));
      downloadCsv(`${exportName}.csv`, lines.join("\r\n"));
      setExportNote(
        truncated
          ? `Exported the first ${all.length} ${noun}s — the collection is longer than this export can walk, so the file is partial.`
          : `Exported ${all.length} ${all.length === 1 ? noun : noun + "s"}.`
      );
    } catch (e) {
      A.toast(mutationMessage(e), "alert", "error");
    } finally {
      setExporting(false);
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const optional = columns.filter((c) => !c.fixed && c.header);
  const span = shown.length + (bulk ? 1 : 0);

  return (
    <div>
      <div className="filter-row" style={{ marginBottom: 14 }}>
        {search && (
          <SearchControl
            value={list.query.q ?? ""}
            fields={search.fields}
            placeholder={search.placeholder}
            onChange={(v) => list.setQuery({ q: v })}
          />
        )}
        {filters}
        <span className="spacer" />
        {toolbar}
        {exportName && (
          <Btn className="btn ghost sm" pending={exporting} onClick={() => void exportCsv()}>
            <Icon name="download" size={14} />
            Export CSV
          </Btn>
        )}
        {optional.length > 0 && (
          <span style={{ position: "relative" }}>
            <button type="button" className="btn ghost sm" aria-expanded={chooser} onClick={() => setChooser((v) => !v)}>
              <Icon name="columns" size={14} />
              Columns
            </button>
            {chooser && (
              <Menu onClose={() => setChooser(false)} align="right">
                <div className="menu-label">Visible columns</div>
                {optional.map((c) => (
                  <button key={c.key} type="button" onClick={() => toggleColumn(c.key)}>
                    <Cbx on={!hidden.includes(c.key)} onChange={() => toggleColumn(c.key)} />
                    {c.header}
                  </button>
                ))}
              </Menu>
            )}
          </span>
        )}
        <PageCount list={list} noun={noun} />
        <PageSize list={list} />
      </div>

      {exportNote && (
        <div className="table-note" role="status">
          <Icon name="alert" size={13} sw={2.2} />
          {exportNote}
        </div>
      )}

      {bulk && selected.length > 0 && (
        <div className="bulk-bar" role="region" aria-label="Bulk actions">
          <b>
            {selected.length} selected
          </b>
          {progress ? (
            <span className="bulk-progress">
              {progress.label}… {progress.done} of {progress.total}
            </span>
          ) : (
            bulk.map((b) => (
              <button
                key={b.label}
                type="button"
                className={"btn sm " + (b.destructive ? "danger-ghost" : "ghost")}
                onClick={() => void runBulk(b)}
              >
                {b.icon && <Icon name={b.icon} size={14} />}
                {b.label}
              </button>
            ))
          )}
          <span className="spacer" />
          <button type="button" className="btn ghost sm" disabled={!!progress} onClick={() => setSelected([])}>
            Clear
          </button>
        </div>
      )}

      {failures.length > 0 && (
        <ViewNotice
          title={`${failures.length} ${failures.length === 1 ? noun : noun + "s"} could not be updated`}
          body={
            <ul style={{ margin: "6px 0 0", paddingLeft: 18, lineHeight: 1.7 }}>
              {failures.map((f) => (
                <li key={f.who}>
                  <span className="mono">{f.who}</span> — {f.why}
                </li>
              ))}
            </ul>
          }
          onRetry={() => setFailures([])}
          retryLabel="Dismiss"
        />
      )}

      {/* `overflow: hidden` on both axes clipped the last column below ~500px
          wide with nothing to scroll — that column's sort button could not be
          reached by pointer or by keyboard. Vertical stays hidden so the card
          keeps its rounded corners. */}
      {list.error ? (
        <ViewNotice title={list.error.title} body={list.error.body} onRetry={list.reload} pending={list.loading} />
      ) : (
        <div className="card" style={{ overflow: overflowVisible ? "visible" : "auto hidden" }}>
          <table className="tbl" aria-label={`${noun}s`}>
            <thead>
              <tr>
                {bulk && (
                  <th scope="col" style={{ width: 38 }}>
                    <Cbx
                      on={allSelected}
                      onChange={(on) => setSelected(on ? keys : [])}
                      label={allSelected ? `Deselect all ${noun}s` : `Select all ${noun}s on this page`}
                    />
                  </th>
                )}
                {shown.map((c) => {
                  const active = !!c.sort && sort === c.sort;
                  return (
                    <th
                      key={c.key}
                      scope="col"
                      className={c.className}
                      aria-sort={active ? (dir === "desc" ? "descending" : "ascending") : c.sort ? "none" : undefined}
                    >
                      {c.sort ? (
                        <button type="button" className={"th-sort" + (active ? " on" : "")} onClick={() => onSort(c)}>
                          {c.header}
                          <Icon
                            name={active && dir === "desc" ? "arrowDown" : "arrowUp"}
                            size={12}
                            sw={2.4}
                            style={{ opacity: active ? 1 : 0.32 }}
                          />
                        </button>
                      ) : (
                        c.header
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const key = rowKey(r);
                const isSel = selected.includes(key);
                // One row-activation site for every paged table in the console.
                const act = onRowClick ? rowActivation(() => onRowClick(r)) : null;
                return (
                  <tr {...act} key={key} className={[act?.className, isSel ? "selected" : null].filter(Boolean).join(" ") || undefined}>
                    {bulk && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <Cbx on={isSel} onChange={() => toggleRow(key)} label={`Select ${key}`} />
                      </td>
                    )}
                    {shown.map((c) => (
                      <td key={c.key} className={c.className}>
                        {c.cell(r)}
                      </td>
                    ))}
                  </tr>
                );
              })}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={span} style={{ textAlign: "center", color: "var(--muted)", padding: 28 }}>
                    {list.loading ? "Loading…" : empty}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {!list.error && <LoadMore list={list} />}
    </div>
  );
}

/**
 * The search control, debounced and self-describing.
 *
 * It states the fields it matches and that the match is a prefix, because the
 * server matches an indexed prefix and nothing else — an operator who types a
 * surname into a username search deserves to be told why it missed rather than
 * to conclude the record is gone.
 */
function SearchControl({
  value,
  fields,
  placeholder,
  onChange,
}: {
  value: string;
  fields: string;
  placeholder?: string;
  onChange: (v: string) => void;
}) {
  const [draft, setDraft] = useState(value);
  // The caller passes an inline arrow, so its identity changes every render. Held
  // in a ref rather than a dependency: a re-render of the table above would
  // otherwise restart the timer below and the search would never commit.
  const commit = useRef(onChange);
  useEffect(() => {
    commit.current = onChange;
  });

  // Follow the committed value when it moves without us — Back, or a pasted URL.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDraft(value);
  }, [value]);

  // One request per pause, not per keystroke — and one history entry per typed
  // word rather than per letter.
  useEffect(() => {
    if (draft === value) return;
    const t = setTimeout(() => commit.current(draft), 350);
    return () => clearTimeout(t);
  }, [draft, value]);

  return (
    <span style={{ display: "inline-flex", flexDirection: "column", gap: 3 }}>
      <SearchBox value={draft} onChange={setDraft} placeholder={placeholder ?? `Search ${fields}…`} />
      <span style={{ fontSize: 11, color: "var(--muted-2)" }}>Matches the start of {fields}</span>
    </span>
  );
}

