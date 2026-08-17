"use client";

import { useEffect, useId, useRef, useState, type ButtonHTMLAttributes, type CSSProperties, type ReactNode } from "react";
import { AlertDialog } from "radix-ui";
import { Icon } from "./icons";
import { PAGE_SIZES, WALK_MAX_PAGES, WALK_PAGE } from "@/lib/console-api";
import { LABELS } from "@/lib/data";
import { avatarHue, fmtTs, initials, utcTs } from "@/lib/helpers";
import type { Key } from "@/lib/types";

/* ---------- Avatar ---------- */
export function Avatar({ name, size = 32, fontSize }: { name: string; size?: number; fontSize?: number }) {
  return (
    <span
      className="avatar"
      style={{
        width: size,
        height: size,
        fontSize: fontSize || Math.round(size * 0.38),
        // L is what decides whether the white initials are legible, and it has
        // to hold for every hue the hash can produce. 0.62 bottomed out at
        // 3.36:1 (blue); 0.52 is 4.95:1 at that same worst hue.
        background: "oklch(0.52 0.14 " + avatarHue(name) + ")",
      }}
    >
      {initials(name)}
    </span>
  );
}

/* ---------- Legacy badges (preview views) ---------- */
export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = { Active: "green", Suspended: "red", Invited: "amber", Inactive: "gray" };
  return (
    <span className={"badge " + (map[status] || "gray")}>
      <span className="bdot" />
      {status}
    </span>
  );
}
export function MfaBadge({ mfa }: { mfa: string }) {
  if (mfa === "Enrolled")
    return (
      <span className="badge green">
        <Icon name="check" size={11} sw={3} />
        Enrolled
      </span>
    );
  if (mfa === "Pending") return <span className="badge gray">Pending</span>;
  return (
    <span className="badge amber">
      <Icon name="alert" size={11} sw={2.4} />
      Not enrolled
    </span>
  );
}
export function ResultBadge({ result }: { result: string }) {
  const map: Record<string, string> = { Success: "green", Failed: "red", Blocked: "red", Flagged: "amber" };
  return (
    <span className={"badge " + (map[result] || "gray")}>
      <span className="bdot" />
      {result}
    </span>
  );
}
export function SeverityBadge({ s }: { s: string }) {
  const map: Record<string, string> = { Critical: "red", High: "amber", Medium: "accent", Low: "gray" };
  return <span className={"badge " + (map[s] || "gray")}>{s}</span>;
}
export function SourceBadge({ source }: { source: string }) {
  return source === "SCIM" ? (
    <span className="badge accent">
      <Icon name="refresh" size={11} sw={2.4} />
      SCIM
    </span>
  ) : (
    <span className="badge gray">Manual</span>
  );
}

/* ---------- Schema badges ---------- */
export function EntityStateBadge({ state }: { state: number }) {
  const map: Record<number, string> = { 1: "green", 2: "gray", 3: "red" };
  return (
    <span className={"badge " + (map[state] || "gray")}>
      <span className="bdot" />
      {LABELS.entityState[state] || state}
    </span>
  );
}
export function UserStateBadge({ state }: { state: number }) {
  const map: Record<number, string> = { 1: "green", 2: "gray", 3: "red", 4: "red", 5: "amber" };
  return (
    <span className={"badge " + (map[state] || "gray")}>
      <span className="bdot" />
      {LABELS.userState[state] || state}
    </span>
  );
}
export function AppTypeBadge({ type }: { type: number }) {
  const map: Record<number, string> = { 1: "accent", 2: "amber", 3: "gray" };
  return <span className={"badge " + (map[type] || "gray")}>{LABELS.appType[type] || type}</span>;
}
export function KeyStateBadge({ k }: { k: Key }) {
  if (k.state === 3) return <span className="badge gray">Retired</span>;
  if (k.state === 2) return <span className="badge gray">Inactive</span>;
  const staged = k.activeAt && new Date(k.activeAt) > new Date();
  if (staged)
    return (
      <span className="badge amber">
        <span className="bdot" />
        Staged
      </span>
    );
  return (
    <span className="badge green">
      <span className="bdot" />
      Active
    </span>
  );
}
export function VerifiedBadge({ on, yes, no }: { on: boolean; yes?: string; no?: string }) {
  return on ? (
    <span className="badge green">
      <Icon name="check" size={11} sw={3} />
      {yes || "Verified"}
    </span>
  ) : (
    <span className="badge amber">
      <Icon name="alert" size={11} sw={2.4} />
      {no || "Pending"}
    </span>
  );
}

/* ---------- Prototype warnings ---------- */
export function ProtoBanner({ children }: { children?: ReactNode }) {
  return (
    <div className="proto-banner" role="status">
      <Icon name="alert" size={18} sw={2} style={{ color: "var(--warn)", flexShrink: 0, marginTop: 1 }} />
      <div>
        <b>Prototype — not functional yet.</b>{" "}
        {children ||
          "This area is not backed by the AlphaOmega schema. Everything shown is a design preview; actions are simulated and nothing is persisted."}
      </div>
    </div>
  );
}
/**
 * A control whose admin endpoint does not exist yet. Rendered disabled with the
 * reason stated — never wired to a toast that claims the write happened. The
 * tooltip lives on the wrapper because a disabled button receives no pointer
 * events, so a `title` on the button itself would never surface.
 */
export function UnbackedBtn({
  reason,
  className = "btn",
  wrapStyle,
  children,
}: {
  reason: string;
  className?: string;
  wrapStyle?: CSSProperties;
  children: ReactNode;
}) {
  return (
    <span title={reason} style={{ display: "inline-flex", ...wrapStyle }}>
      <button type="button" className={className} style={{ width: "100%" }} disabled title={reason}>
        {children}
      </button>
    </span>
  );
}
export function FutureTag({ label }: { label?: string }) {
  return (
    <span className="badge amber future-tag">
      <Icon name="clock" size={11} sw={2.4} />
      {label || "Coming soon"}
    </span>
  );
}

/* ---------- Confirmation ---------- */

export interface ConfirmOptions {
  title: string;
  /** State the consequence, not just the object. */
  body: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
}

interface ConfirmRequest extends ConfirmOptions {
  resolve: (ok: boolean) => void;
}

let openConfirm: ((req: ConfirmRequest) => void) | null = null;

/**
 * The console's replacement for `window.confirm`, in-brand and awaited the same
 * way: `if (!(await confirmAction({ ... }))) return;`.
 *
 * Resolves `false` when no `<ConfirmHost>` is mounted, so a missing host fails
 * closed — it can never turn into an unconfirmed destructive write.
 */
export function confirmAction(opts: ConfirmOptions): Promise<boolean> {
  if (!openConfirm) return Promise.resolve(false);
  return new Promise((resolve) => openConfirm?.({ ...opts, resolve }));
}

/** Mounted once in the console layout; renders whatever `confirmAction` asks. */
export function ConfirmHost() {
  const [req, setReq] = useState<ConfirmRequest | null>(null);
  const live = useRef<ConfirmRequest | null>(null);

  useEffect(() => {
    openConfirm = (r) => {
      live.current = r;
      setReq(r);
    };
    return () => {
      openConfirm = null;
    };
  }, []);

  function settle(ok: boolean) {
    const r = live.current;
    live.current = null;
    setReq(null);
    r?.resolve(ok);
  }

  return (
    <AlertDialog.Root
      open={!!req}
      onOpenChange={(open) => {
        if (!open) settle(false);
      }}
    >
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="overlay" />
        <AlertDialog.Content className="modal confirm-modal">
          <AlertDialog.Title className="confirm-title">{req?.title}</AlertDialog.Title>
          <AlertDialog.Description asChild>
            <div className="confirm-body">{req?.body}</div>
          </AlertDialog.Description>
          <div className="confirm-foot">
            <AlertDialog.Cancel className="btn ghost">Cancel</AlertDialog.Cancel>
            <AlertDialog.Action className={"btn " + (req?.destructive ? "danger" : "primary")} onClick={() => settle(true)}>
              {req?.confirmLabel || "Confirm"}
            </AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

/* ---------- Buttons ---------- */

/** A `.btn` that goes disabled and shows a spinner while its write is in flight. */
export function Btn({
  pending,
  disabled,
  className = "btn",
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { pending?: boolean }) {
  return (
    <button type="button" {...rest} className={className} disabled={disabled || pending} aria-busy={pending || undefined}>
      {pending && <Icon name="refresh" size={14} sw={2.4} style={{ animation: "spin 0.9s linear infinite" }} />}
      {children}
    </button>
  );
}

/* ---------- View states ---------- */

/**
 * A named failure, permission refusal, or empty state inside a card — with a
 * retry where one makes sense. A view renders this instead of a blank table so
 * "no data" is never ambiguous between broken, forbidden, and genuinely empty.
 */
export function ViewNotice({
  title,
  body,
  icon = "alert",
  onRetry,
  retryLabel = "Retry",
  pending,
}: {
  title: string;
  body?: ReactNode;
  icon?: string;
  onRetry?: () => void;
  retryLabel?: string;
  pending?: boolean;
}) {
  return (
    <div className="card view-notice" role="status">
      <Icon name={icon} size={18} sw={2} style={{ color: "var(--muted-2)", flexShrink: 0, marginTop: 2 }} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <b>{title}</b>
        {body ? <p>{body}</p> : null}
      </div>
      {onRetry && (
        <Btn className="btn ghost sm" pending={pending} onClick={onRetry}>
          {retryLabel}
        </Btn>
      )}
    </div>
  );
}

/* ---------- Paged list chrome ---------- */

/** The shape `usePagedList` returns, narrowed to what this file renders — kept
 * structural so primitives stay independent of the store. */
interface PagedView {
  items: unknown[];
  total: number | null;
  page: number;
  totalPages: number;
  setPage: (n: number) => void;
  loading: boolean;
  pageSize: number;
  setPageSize: (n: number) => void;
}

/** What the pager reads. Narrower than `PagedView`, so a view that holds its own
 * page state (the audit feed does) can render the same control. */
interface PagerView {
  page: number;
  totalPages: number;
  setPage: (n: number) => void;
  loading: boolean;
}

/** How many numbered buttons the pager renders around the current page. */
const PAGER_WINDOW = 5;

// pageWindow names the pages the pager offers directly: PAGER_WINDOW of them,
// centred on the current page and pushed inside 1..totalPages at both ends, so
// the pager keeps its width wherever the operator is.
function pageWindow(page: number, totalPages: number): number[] {
  const start = Math.max(1, Math.min(page - Math.floor(PAGER_WINDOW / 2), totalPages - PAGER_WINDOW + 1));
  const end = Math.min(totalPages, start + PAGER_WINDOW - 1);
  const out: number[] = [];
  for (let n = start; n <= end; n++) out.push(n);
  return out;
}

/**
 * The pager: first, previous, the numbered pages, next, last.
 *
 * An operator names a page and goes to it. A page number has an address before
 * anyone has walked to it, which is what the offset window buys and a cursor
 * window cannot give. See `docs/adr/0007-offset-pagination-for-admin-lists.md`.
 */
export function Pager({ list }: { list: PagerView }) {
  if (list.totalPages <= 1) return null;

  const go = (n: number) => () => list.setPage(n);
  const step = (label: string, to: number, disabled: boolean, glyph: string) => (
    <Btn key={label} className="btn ghost sm" disabled={disabled || list.loading} onClick={go(to)} aria-label={label}>
      <span aria-hidden="true">{glyph}</span>
    </Btn>
  );

  return (
    <nav aria-label="Pagination" style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14 }}>
      {step("First page", 1, list.page <= 1, "«")}
      {step("Previous page", list.page - 1, list.page <= 1, "‹")}
      {pageWindow(list.page, list.totalPages).map((n) => (
        <Btn
          key={n}
          className={n === list.page ? "btn sm" : "btn ghost sm"}
          disabled={list.loading}
          onClick={go(n)}
          aria-label={`Page ${n}`}
          aria-current={n === list.page ? "page" : undefined}
        >
          {n}
        </Btn>
      ))}
      {step("Next page", list.page + 1, list.page >= list.totalPages, "›")}
      {step("Last page", list.totalPages, list.page >= list.totalPages, "»")}
    </nav>
  );
}

/**
 * The page-size control. Its options ARE the set the API serves (PAGE_SIZES), so
 * no selection can be a size the gateway refuses — which is the reason the set is
 * fixed at all. Changing it restarts the list from the head; see
 * `usePagedList.setPageSize`.
 */
export function PageSize({ list }: { list: PagedView }) {
  const id = useId();
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12.5, color: "var(--muted)" }}>
      <label htmlFor={id}>Rows</label>
      <SelectInput
        id={id}
        width={72}
        value={String(list.pageSize)}
        options={PAGE_SIZES.map(String)}
        onChange={(v) => list.setPageSize(Number(v))}
      />
    </span>
  );
}

/** A picker that stopped before the end of its collection says so. A short
 * `<select>` that stays quiet is indistinguishable from a complete one — the
 * failure this whole paging contract exists to remove. */
export function PickerTruncated({ what }: { what: string }) {
  return (
    <div style={{ marginTop: 6, fontSize: 12, color: "var(--warn)", display: "flex", alignItems: "center", gap: 6 }}>
      <Icon name="alert" size={12} sw={2.2} />
      Showing the first {WALK_PAGE * WALK_MAX_PAGES} {what} — the list is longer than this picker can hold.
    </div>
  );
}

/** Which rows of a paged list are on screen: the range this page covers, out of
 * the server's scoped total. It names the range rather than a count, because on
 * page 3 a bare "50" reads as the first 50. Renders nothing when the API sent no
 * total. */
export function PageCount({ list, noun }: { list: PagedView; noun: string }) {
  if (list.total === null) return null;
  const label = `${list.total} ${list.total === 1 ? noun : noun + "s"}`;
  if (list.items.length === 0 || list.items.length >= list.total) return <span className="badge gray">{label}</span>;

  const first = (list.page - 1) * list.pageSize + 1;
  return <span className="badge gray">{`${first}–${first + list.items.length - 1} of ${label}`}</span>;
}

/* ---------- Small helpers ---------- */

/** Writes to the clipboard and confirms only once the write actually resolved. */
export async function copyToClipboard(value: string, label: string, toast?: (msg: string, icon?: string, severity?: "success" | "error" | "info") => void) {
  try {
    await navigator.clipboard.writeText(value);
    toast?.("Copied " + label, "copy");
  } catch {
    toast?.("Clipboard unavailable", "alert", "error");
  }
}

export function MonoChip({
  value,
  short,
  toast,
}: {
  value: string;
  short?: boolean;
  toast?: (msg: string, icon?: string, severity?: "success" | "error" | "info") => void;
}) {
  const display = short ? value.slice(0, 8) + "…" : value;
  return (
    <button
      type="button"
      className="mono-chip"
      title={value}
      onClick={(e) => {
        e.stopPropagation();
        void copyToClipboard(value, display, toast);
      }}
    >
      {display}
      <Icon name="copy" size={11} sw={2} />
    </button>
  );
}
/**
 * A rendered timestamp: local time with its zone named, the exact UTC value one
 * hover away. The ONE place a time reaches the screen.
 *
 * `suppressHydrationWarning` because the server and the browser are not in the
 * same timezone — the browser's rendering is the correct one, and React would
 * otherwise report the difference as a hydration error on every list.
 */
export function Ts({ value, empty = "—" }: { value?: string | null; empty?: string }) {
  if (!value) return <>{empty}</>;
  return (
    <span title={utcTs(value)} suppressHydrationWarning>
      {fmtTs(value)}
    </span>
  );
}

export function KV({ k, v }: { k: ReactNode; v: ReactNode }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  );
}

/* ---------- Form bits ---------- */

/**
 * A labelled control.
 *
 * The control is a DESCENDANT of the `<label>`, so the association is
 * structural — no `id` to generate, pass down, and keep in step at 39 call
 * sites. Use it wherever the label names exactly one control.
 *
 * Where it does not — a heading over a group of controls, a label sharing its
 * row with an override switch, a value that is only rendered — this is the
 * wrong component: an implicit label binds to the FIRST labelable descendant,
 * so a second one silently loses its name. Those sites pair a `useId` with an
 * explicit `htmlFor`, or drop `<label>` for a `<span>` when there is no control
 * to name at all.
 */
export function Field({ label, style, children }: { label: ReactNode; style?: CSSProperties; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label" style={style}>
        {label}
      </span>
      {children}
    </label>
  );
}

export function Cbx({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button
      type="button"
      className={"cbx" + (on ? " on" : "")}
      role="checkbox"
      aria-checked={on}
      aria-label={label}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!on);
      }}
    >
      <Icon name="check" size={11} sw={3.5} />
    </button>
  );
}
export function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button
      type="button"
      className={"toggle" + (on ? " on" : "")}
      role="switch"
      aria-checked={on}
      aria-label={label}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!on);
      }}
    />
  );
}
export function Seg({
  options,
  value,
  onChange,
  label,
}: {
  options: string[];
  value: string;
  onChange: (v: string) => void;
  /** Names the whole group — a `<label>` cannot, because a segmented control is
   * several buttons and an implicit label would claim only the first. */
  label?: string;
}) {
  return (
    <div className="seg" role="tablist" aria-label={label}>
      {options.map((o) => (
        <button key={o} type="button" role="tab" aria-selected={value === o} className={value === o ? "on" : ""} onClick={() => onChange(o)}>
          {o}
        </button>
      ))}
    </div>
  );
}
export function SearchBox({
  value,
  onChange,
  placeholder,
  width,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  width?: number;
}) {
  return (
    <div className="search-box" style={{ width: width || 260 }}>
      <Icon name="search" size={15} />
      {/* The placeholder IS the visible label here — there is no other text to
          associate, and reusing it means the two cannot disagree. */}
      <input className="text-input" value={value} placeholder={placeholder} aria-label={placeholder} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
export function SelectInput({
  value,
  options,
  onChange,
  width,
  id,
  label,
}: {
  value: string;
  options: string[];
  onChange: (v: string) => void;
  width?: number;
  /** For the sites whose visible label cannot wrap the control — it shares its
   * row with something else, or the control renders conditionally. */
  id?: string;
  label?: string;
}) {
  return (
    <select
      className="text-input select-input"
      id={id}
      aria-label={label}
      style={width ? { width } : undefined}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}
export function OptChip({ on, label, onChange }: { on: boolean; label: string; onChange: (v: boolean) => void }) {
  return (
    <button type="button" className={"chip opt-chip" + (on ? " on" : "")} aria-pressed={on} onClick={() => onChange(!on)}>
      {on && <Icon name="check" size={11} sw={3} />}
      {label}
    </button>
  );
}
