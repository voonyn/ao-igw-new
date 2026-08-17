"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Icon } from "@/components/console/icons";
import { Avatar, Btn, copyToClipboard, Pager, ResultBadge, SearchBox, SelectInput, Ts, ViewNotice } from "@/components/console/primitives";
import { csvCell, downloadCsv } from "@/lib/csv";
import { useConsole } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { rowActivation } from "@/components/console/data-table";
import { auditApi, describeStatus, type AuditEvent } from "@/lib/console-api";

/** The noun and role every audit refusal is phrased from — one gate in the view,
 * one 403 from the gateway, one sentence. */
const AUDIT_RESOURCE = "the audit log";
const AUDIT_ROLE = "IAM_OWNER or IAM_ADMIN";

// Human labels for the known action taxonomy; unknown actions fall back to the
// raw action string (shown in mono under the label).
const ACTION_LABEL: Record<string, string> = {
  "login.succeeded": "Sign-in",
  "login.failed": "Sign-in failed",
  logout: "Sign-out",
  "consent.granted": "Consent granted",
  "consent.denied": "Consent denied",
  "password.reset": "Password reset",
  "password.changed": "Password changed",
  "email.verified": "Email verified",
  "account.locked": "Account locked",
  "account.unlocked": "Account unlocked",
  "mfa.recovery_code_used": "Recovery code used",
  "mfa.recovery_codes_regenerated": "Recovery codes replaced",
  "user.created": "User created",
  "user.updated": "User updated",
  "user.deactivated": "User deactivated",
  "user.deleted": "User deleted",
  "member.added": "Member added",
  "member.role_changed": "Member roles changed",
  "member.removed": "Member removed",
  "client.secret_rotated": "Client secret rotated",
  "domain.added": "Tenant domain added",
  "domain.removed": "Tenant domain removed",
  "signing_key.rotated": "Signing key rotated",
  "signing_key.retired": "Signing key retired",
};

function labelOf(action: string): string {
  return ACTION_LABEL[action] ?? action;
}

// categoryOf groups an action for DISPLAY in the expanded row. It was a filter
// segment until this change: derived from the action prefix, so it could only
// ever narrow the events already fetched — on a busy tenant it hid the ones it
// could not see. Narrowing is now `action`, which the API matches in the query.
function categoryOf(action: string): string {
  // Spending a recovery code means the authenticator was unavailable — the same
  // class of signal as a failed sign-in or a lockout, not an administrative event.
  if (action === "login.failed" || action === "mfa.recovery_code_used" || action.startsWith("account.")) return "Risk";
  if (action.startsWith("login.") || action === "logout" || action.startsWith("consent.")) return "Auth";
  return "Admin";
}

/** The action `<select>`'s options: "All actions" plus the known taxonomy. An
 * action outside it is still readable in the feed — this narrows, it does not
 * define what exists. */
const ACTION_OPTIONS = ["All actions", ...Object.keys(ACTION_LABEL).map((a) => `${ACTION_LABEL[a]} (${a})`)];

// actionOf turns an option label back into the raw action the API matches.
function actionOf(label: string): string | undefined {
  const m = /\(([^)]+)\)$/.exec(label);
  return m ? m[1] : undefined;
}

/** How many pages the CSV export follows before it stops and says so — the same
 * bound the pickers use, for the same reason: a file that silently ends is
 * indistinguishable from a complete one. */
const EXPORT_MAX_PAGES = 10;
const EXPORT_PAGE = 100;

/** Rows per page in the feed. The pager addresses the rest. */
const PAGE_SIZE = 100;

function resultLabel(result: string): string {
  return result === "failure" ? "Failed" : "Success";
}

function actorLabel(e: AuditEvent): string {
  if (e.actor) return e.actor;
  return e.result === "failure" ? "Unknown" : "System";
}

export function AuditView() {
  const { me, A } = useConsole();

  // Reads are tenant-manager scoped (matches the sidebar gate + the API).
  // Refused here rather than by the gateway, but it is the same refusal, so it
  // resolves the same sentence.
  if (!me.isTenantManager) {
    const gate = describeStatus({ state: "forbidden" }, AUDIT_RESOURCE, AUDIT_ROLE)!;
    return (
      <div className="fade-in">
        <PageHead
          page="audit"
          sub="Immutable record of every administrative and authentication event."
        />
        <ViewNotice title={gate.title} body={gate.body} icon="lock" />
      </div>
    );
  }

  return <AuditLog toast={A.toast} />;
}

/**
 * The audit feed.
 *
 * `fixed` pins part of the query and hides the controls for it, which is how the
 * user detail view asks for "events this person performed" (`actor`) and "events
 * performed on this person" (`entityId`) — two reads, because the repository
 * ANDs its predicates and cannot express the OR.
 */
export function AuditLog({
  toast,
  fixed,
  title,
}: {
  toast: (msg: string, icon?: string, severity?: "success" | "error" | "info") => void;
  fixed?: { actor?: string; entityId?: string };
  title?: ReactNode;
}) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{ title: string; body: string } | null>(null);
  const [action, setAction] = useState("All actions");
  const [actor, setActor] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exportNote, setExportNote] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  // The narrowing that reaches the QUERY. Every control here maps to a predicate
  // the audit repository applies — there is no client-side pass left, which is
  // what makes "no events match" mean the tenant holds none rather than that the
  // pages fetched so far held none.
  const query = useMemo(
    () => ({ ...fixed, action: actionOf(action), actor: fixed?.actor ?? (actor.trim() || undefined) }),
    [fixed, action, actor]
  );

  // The page on screen. `loaded` is set in `finally` — a failed read must render
  // an error, not a card that is blank forever because neither branch ran.
  const load = useCallback(() => {
    return auditApi
      .list({ ...query, limit: PAGE_SIZE, page })
      .then((out) => {
        setError(null);
        if (!out.ok) {
          setEvents([]);
          setTotalPages(0);
          setError(describeStatus({ state: out.reason }, AUDIT_RESOURCE, AUDIT_ROLE));
          return;
        }
        setEvents(out.data.items);
        setTotalPages(out.data.totalPages);
      })
      .catch((e: unknown) =>
        setError(describeStatus({ state: "error", message: e instanceof Error ? e.message : "" }, AUDIT_RESOURCE))
      )
      .finally(() => {
        setLoaded(true);
        setLoading(false);
      });
  }, [query, page]);

  useEffect(() => {
    // The pending flag has to flip before the request is issued — it IS the
    // synchronization with the external system, not a render derived from one.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(true);
    void load();
  }, [load]);

  // A narrowing change sends the feed back to page one: page 3 of the old filter
  // is not page 3 of the new one.
  const narrow = useCallback(<T,>(set: (v: T) => void) => (v: T) => {
    setPage(1);
    set(v);
  }, []);

  // Export walks the pages under the same bound, with the same filters the table
  // is showing — no export endpoint, and no chance of the file disagreeing with
  // the screen.
  async function exportCsv() {
    setExporting(true);
    setExportNote(null);
    try {
      let rows: AuditEvent[] = [];
      let truncated = false;
      for (let n = 1; n <= EXPORT_MAX_PAGES; n++) {
        const out = await auditApi.list({ ...query, limit: EXPORT_PAGE, page: n });
        if (!out.ok) break;
        rows = rows.concat(out.data.items);
        if (n >= out.data.totalPages) break;
        truncated = n === EXPORT_MAX_PAGES;
      }
      const head = ["Time", "Actor", "Action", "Entity type", "Entity ID", "Result", "IP", "User agent"];
      const lines = [head.map(csvCell).join(",")];
      for (const e of rows) {
        lines.push(
          [e.createdAt, actorLabel(e), e.action, e.entityType, e.entityId ?? "", e.result, e.ip ?? "", e.userAgent ?? ""]
            .map(csvCell)
            .join(",")
        );
      }
      downloadCsv("audit.csv", lines.join("\r\n"));
      setExportNote(
        truncated
          ? `Exported the first ${rows.length} events — the feed is longer than this export can walk, so the file is partial.`
          : `Exported ${rows.length} ${rows.length === 1 ? "event" : "events"}.`
      );
    } catch {
      toast("Couldn’t export the audit log", "alert", "error");
    } finally {
      setExporting(false);
    }
  }

  let lastDate: string | null = null;
  const rows: ReactNode[] = [];
  for (const e of events) {
    // The date separator groups by LOCAL day, which is the day the operator is
    // reading; the per-row cell states the zone, so the grouping cannot be read
    // as a claim about UTC.
    const when = new Date(e.createdAt);
    const date = when.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
    const actor = actorLabel(e);
    const target = e.entityId || e.entityType;
    const result = resultLabel(e.result);
    const category = categoryOf(e.action);
    const isOpen = open === e.id;

    if (date !== lastDate) {
      lastDate = date;
      rows.push(
        <tr key={e.id + "-d"}>
          <td colSpan={6} style={{ background: "var(--field)", padding: "6px 14px", fontSize: 11, fontWeight: 600, letterSpacing: "0.07em", textTransform: "uppercase", color: "var(--muted)" }}>
            <span suppressHydrationWarning>{date}</span>
          </td>
        </tr>,
      );
    }

    rows.push(
      <tr key={e.id} {...rowActivation(() => setOpen(isOpen ? null : e.id))} className={"clickable" + (isOpen ? " selected" : "")}>
        <td className="mono">
          <Ts value={e.createdAt} />
        </td>
        <td>
          <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
            {actor === "System" || actor === "Unknown" ? (
              <span
                style={{
                  width: 26,
                  height: 26,
                  borderRadius: "50%",
                  background: actor === "Unknown" ? "var(--error-soft)" : "var(--border-soft)",
                  color: actor === "Unknown" ? "var(--error)" : "var(--muted)",
                  display: "grid",
                  placeItems: "center",
                  flexShrink: 0,
                }}
              >
                <Icon name={actor === "Unknown" ? "alert" : "settings"} size={13} />
              </span>
            ) : (
              <Avatar name={actor} size={26} />
            )}
            <span style={{ fontWeight: 500, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} className={e.actor ? "mono" : ""}>
              {actor}
            </span>
          </div>
        </td>
        <td>
          <div style={{ fontWeight: 500 }}>{labelOf(e.action)}</div>
          <div className="mono" style={{ fontSize: 11.5 }}>
            {e.action}
          </div>
        </td>
        <td className="hide-md" style={{ maxWidth: 230 }}>
          <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{target}</span>
        </td>
        <td>
          <ResultBadge result={result} />
        </td>
        <td>
          <Icon name="chevD" size={15} style={{ color: "var(--muted-2)", transform: isOpen ? "rotate(180deg)" : "none", transition: "transform 0.18s ease" }} />
        </td>
      </tr>,
    );

    if (isOpen) {
      rows.push(
        <tr key={e.id + "-x"}>
          <td colSpan={6} style={{ background: "var(--field)", padding: "14px 18px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, fontSize: 12.5 }}>
              {[
                { k: "Event ID", v: e.id },
                { k: "Source IP", v: e.ip || "—" },
                { k: "Entity", v: e.entityType },
                { k: "Category", v: category },
              ].map((f) => (
                <div key={f.k}>
                  <div style={{ fontSize: 10.5, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--muted-2)", marginBottom: 4 }}>{f.k}</div>
                  <div className="mono" style={{ color: "var(--ink)", fontSize: 12.5, overflowWrap: "anywhere" }}>
                    {f.v}
                  </div>
                </div>
              ))}
            </div>
            {e.userAgent && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 10.5, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--muted-2)", marginBottom: 4 }}>User agent</div>
                <div className="mono" style={{ color: "var(--ink)", fontSize: 12, overflowWrap: "anywhere" }}>
                  {e.userAgent}
                </div>
              </div>
            )}
            <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
              <button className="btn sm ghost" onClick={() => A_copy(e, toast)}>
                <Icon name="copy" size={13} />
                Copy event JSON
              </button>
            </div>
          </td>
        </tr>,
      );
    }
  }

  return (
    <div className="fade-in">
      {title ?? (
        <PageHead
          page="audit"
          sub="Immutable record of every administrative and authentication event for this tenant."
        />
      )}

      <div className="filter-row" style={{ marginBottom: 14 }}>
        <SelectInput width={260} value={action} options={ACTION_OPTIONS} onChange={narrow(setAction)} />
        {!fixed?.actor && (
          <span style={{ display: "inline-flex", flexDirection: "column", gap: 3 }}>
            <SearchBox value={actor} onChange={narrow(setActor)} placeholder="Actor user ID…" width={300} />
            <span style={{ fontSize: 11, color: "var(--muted-2)" }}>Matches the actor’s user ID exactly</span>
          </span>
        )}
        <span className="spacer" />
        <Btn className="btn ghost sm" pending={exporting} onClick={() => void exportCsv()}>
          <Icon name="download" size={14} />
          Export CSV
        </Btn>
      </div>

      {exportNote && (
        <div className="table-note" role="status">
          <Icon name="alert" size={13} sw={2.2} />
          {exportNote}
        </div>
      )}

      {error ? (
        <ViewNotice title={error.title} body={error.body} onRetry={() => void load()} pending={!loaded} />
      ) : (
      <div className="card">
        <table className="tbl" aria-label="Audit events">
          <thead>
            <tr>
              <th scope="col" style={{ width: 92 }}>Time</th>
              <th scope="col">Actor</th>
              <th scope="col">Event</th>
              <th scope="col" className="hide-md">Target</th>
              <th scope="col">Result</th>
              <th scope="col" style={{ width: 36 }}></th>
            </tr>
          </thead>
          <tbody>
            {rows}
            {loaded && events.length === 0 && (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", padding: "36px 0", color: "var(--muted)" }}>
                  No audit events match this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      )}

      {!error && <Pager list={{ page, totalPages, setPage, loading }} />}
    </div>
  );
}

/**
 * "What was done to this record", as a detail-route tab.
 *
 * Only the `entityId` half of the user tab's segmented choice: an organization
 * or an application is never an actor, so there is nothing to segment. It rides
 * on the `audit_events.entity_id` index 00035 added — without it this read
 * scanned, which is why it was not offered before.
 */
export function EntityAuditTab({ entityId, noun }: { entityId: string; noun: string }) {
  const { me, A } = useConsole();

  // Renders and states the role rather than disappearing — a console that
  // differs by role without saying so reads as a missing feature. Same refusal
  // as the full view, so the same sentence; the noun only adds why it is not
  // narrowed to the org the record belongs to.
  if (!me.isTenantManager) {
    const gate = describeStatus({ state: "forbidden" }, AUDIT_RESOURCE, AUDIT_ROLE)!;
    return (
      <ViewNotice
        title={gate.title}
        body={`${gate.body} Organization-scoped audit is not offered, so this ${noun}'s events are not available either.`}
        icon="lock"
      />
    );
  }
  return <AuditLog toast={A.toast} title={null} fixed={{ entityId }} />;
}

// A_copy copies the event as JSON, confirming only once the write resolved.
function A_copy(e: AuditEvent, toast: (msg: string, icon?: string, severity?: "success" | "error" | "info") => void) {
  void copyToClipboard(JSON.stringify(e, null, 2), "event JSON", toast);
}
