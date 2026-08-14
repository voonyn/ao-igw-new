"use client";

import { useState } from "react";
import { Icon } from "@/components/console/icons";
import { Avatar, Btn, confirmAction, KV, MonoChip, Seg, SelectInput, Ts } from "@/components/console/primitives";
import { DataTable, type BulkAction, type Column } from "@/components/console/data-table";
import { Drawer } from "@/components/console/overlays";
import { usePagedList, usePending } from "@/components/console/store";
import { canWriteOrg, pages, sessionsApi, type Me } from "@/lib/console-api";
import { nameOr, orUnknown } from "@/lib/helpers";
import type { Grant, LoginSession } from "@/lib/types";
import { useConsole } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";

// Org roles that may revoke a user's sessions — the gateway gates force-logout
// on the session owner's org with exactly this set.
const SESSION_WRITE_ROLES = ["ORG_OWNER", "ORG_USER_MANAGER"];

function SessionDrawer({
  session,
  canWrite,
  onClose,
}: {
  session: LoginSession;
  canWrite: boolean;
  onClose: () => void;
}) {
  const who = nameOr(session.userName, session.userId);
  const [busy, run] = usePending();

  // A real revocation: terminate server-side, then re-read. Unlike a user's own
  // sign-out this also kills offline_access grants, so no refresh token survives.
  async function terminate() {
    const ok = await confirmAction({
      title: "Terminate this session?",
      body: `${who} is signed out of every app on this session immediately, and its token grants are revoked — refresh tokens included, so nothing can be renewed. Access tokens already issued live out their remaining TTL at the relying party.`,
      confirmLabel: "Terminate session",
      destructive: true,
    });
    if (!ok) return;
    if (await run(() => sessionsApi.revoke(session.id), { ok: "Session terminated — grants revoked", icon: "ban" })) onClose();
  }
  return (
    <Drawer title={`Session for ${who}`} onClose={onClose} width={480}>
      <div className="drawer-head">
        <Avatar name={who} size={34} />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 15 }}>{who}</div>
          <div style={{ fontSize: 12, color: "var(--muted)", fontFamily: "var(--font-mono)" }}>sid {session.id}</div>
        </div>
        <span style={{ marginLeft: "auto" }}>
          {session.state === 1 ? (
            <span className="badge green">
              <span className="bdot" />
              Active
            </span>
          ) : (
            <span className="badge gray">Terminated</span>
          )}
        </span>
        <button type="button" className="icon-btn" aria-label="Close" onClick={onClose}>
          <Icon name="x" size={17} />
        </button>
      </div>
      <div className="drawer-body">
        <div className="drawer-sect">
          <div className="sect-title">Verified factors</div>
          {session.factors.map((f) => (
            <KV
              key={f.amr}
              k={
                <span className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
                  {f.amr}
                </span>
              }
              v={
                <>
                  verified at <Ts value={f.time} />
                </>
              }
            />
          ))}
          {session.factors.length === 0 && (
            <div style={{ fontSize: 13, color: "var(--muted)" }}>Not available — this session&rsquo;s stored state could not be decoded.</div>
          )}
        </div>
        <div className="drawer-sect">
          <div className="sect-title">Context</div>
          <KV k="Created" v={<Ts value={session.created} />} />
          <KV
            k="Expires"
            v={
              <>
                <Ts value={session.expires} /> (slides on activity)
              </>
            }
          />
          {/* Recorded at mint and never refreshed — RecordFactor re-seals them
              unchanged and sliding expiry does not touch the blob — so these are
              where the session began, not where it was last seen. */}
          <KV k="IP address (at sign-in)" v={<span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{orUnknown(session.ip)}</span>} />
          <KV k="User agent (at sign-in)" v={orUnknown(session.ua)} />
          <KV k="Session token" v={<span style={{ color: "var(--muted)" }}>SHA-256 digest only — rotated per factor upgrade</span>} />
        </div>
        {/* ponytail: the protocol links carry the app id from the session blob, not
            a name — nothing joins them, and resolving one per link would be a
            request per row. The grants tab names its clients; add
            GET /sessions/:id/grants if operators ask for names here too. */}
        <div className="drawer-sect">
          <div className="sect-title">Protocol links ({session.links.length})</div>
          {session.links.map((l, i) => (
            <div className="kv" key={i}>
              <span className="k" style={{ color: "var(--ink)", fontWeight: 500, display: "flex", alignItems: "center", gap: 8 }}>
                <Icon name="link" size={14} style={{ color: "var(--muted)" }} />
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>{l.appId}</span>
              </span>
              <span className="v" style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--muted)" }}>oidc · {l.ref}</span>
            </div>
          ))}
          {session.links.length === 0 && <div style={{ fontSize: 13, color: "var(--muted)" }}>No protocol flows attached to this session.</div>}
        </div>
      </div>
      <div className="drawer-foot">
        {session.state === 1 && canWrite && (
          <Btn className="btn danger-ghost" pending={busy} onClick={terminate}>
            <Icon name="logout" size={15} />
            Terminate session
          </Btn>
        )}
        <button type="button" className="btn ghost" style={{ marginLeft: "auto" }} onClick={onClose}>
          Close
        </button>
      </div>
    </Drawer>
  );
}

/** A session's state is a LIFECYCLE, not a soft delete: the admin read no longer
 * hides terminated sessions, because an operator investigating an account needs
 * to see that a session ended and when. So it is a filter the caller chooses. */
const SESSION_STATES: { label: string; value?: number }[] = [
  { label: "All states" },
  { label: "Active", value: 1 },
  { label: "Terminated", value: 2 },
];

/** The Sessions table's columns and its bulk terminate. Shared with the user
 * detail view's Sessions tab, which is the same read narrowed to one subject. */
export function sessionColumns(): Column<LoginSession>[] {
  return [
    {
      key: "user",
      header: "User",
      fixed: true,
      text: (s) => nameOr(s.userName, s.userId),
      cell: (s) => (
        <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Avatar name={nameOr(s.userName, s.userId)} size={28} />
          <span style={{ fontWeight: 600 }}>{nameOr(s.userName, s.userId)}</span>
        </span>
      ),
    },
    {
      key: "factors",
      header: "Factors",
      text: (s) => s.factors.map((f) => f.amr).join(" ") || "—",
      // An empty chip row is indistinguishable from a row that has not loaded, so
      // an undecodable session says so rather than rendering nothing.
      cell: (s) =>
        s.factors.length === 0 ? (
          <span style={{ color: "var(--muted)" }}>—</span>
        ) : (
          <span className="chip-row">
            {s.factors.map((f) => (
              <span key={f.amr} className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                {f.amr}
              </span>
            ))}
          </span>
        ),
    },
    // Apps counts PROTOCOL LINKS — the relying parties this session signed into
    // — not live grants. See the drawer's "Protocol links" section, which reads
    // the same array.
    { key: "apps", header: "Apps", className: "hide-md mono", text: (s) => String(s.links.length), cell: (s) => s.links.length },
    {
      key: "ip",
      header: "IP",
      className: "hide-md mono",
      text: (s) => orUnknown(s.ip),
      cell: (s) => orUnknown(s.ip),
    },
    {
      key: "created",
      header: "Created",
      className: "hide-md mono",
      sort: "created",
      defaultDir: "desc",
      text: (s) => s.created,
      cell: (s) => <Ts value={s.created} />,
    },
    {
      key: "expires",
      header: "Expires",
      className: "mono",
      sort: "expires",
      defaultDir: "desc",
      text: (s) => s.expires,
      cell: (s) => <Ts value={s.expires} />,
    },
    {
      key: "state",
      header: "State",
      sort: "state",
      text: (s) => (s.state === 1 ? "Active" : "Terminated"),
      cell: (s) =>
        s.state === 1 ? (
          <span className="badge green">
            <span className="bdot" />
            Active
          </span>
        ) : (
          <span className="badge gray">Terminated</span>
        ),
    },
  ];
}

/** Terminate, as a bulk action: N of the same `DELETE /sessions/:id` the drawer
 * issues, one confirmation, and a per-row result. There is no batch endpoint —
 * so authorization, auditing, and error mapping are unchanged by construction. */
export function terminateBulk(me: Me): BulkAction<LoginSession> {
  return {
    label: "Terminate",
    icon: "logout",
    destructive: true,
    // An already-terminated session is skipped rather than failed, and a session
    // in an org the caller cannot write is not attempted at all.
    applies: (s) => s.state === 1 && canWriteOrg(me, s.orgId, SESSION_WRITE_ROLES),
    describe: (s) => nameOr(s.userName, s.userId),
    run: (s) => sessionsApi.revoke(s.id),
    confirm: (n) => ({
      title: `Terminate ${n} ${n === 1 ? "session" : "sessions"}?`,
      body: "Each user is signed out of every app on that session immediately and its token grants are revoked — refresh tokens included, so nothing can be renewed. Access tokens already issued live out their remaining TTL at the relying party.",
      confirmLabel: "Terminate",
      destructive: true,
    }),
  };
}

export function SessionsView() {
  const { me, A } = useConsole();
  const [tab, setTab] = useState("Login sessions");
  const [openId, setOpenId] = useState<string | null>(null);
  // Both tabs page independently and both stay mounted, so switching tabs does
  // not throw away the pages the other one already walked. Only the sessions
  // half claims the URL: two mounted lists writing the same `sort` would each
  // read the other's.
  const sessions = usePagedList(pages.sessions, "sessions", { urlSync: true });
  const grants = usePagedList(pages.grants, "grants");
  const isSessions = tab === "Login sessions";
  const open = sessions.items.find((s) => s.id === openId);
  const stateLabel = SESSION_STATES.find((s) => s.value === sessions.query.state)?.label ?? "All states";

  const grantColumns: Column<Grant>[] = [
    { key: "id", header: "Grant", fixed: true, text: (g) => g.id, cell: (g) => <MonoChip value={g.id} toast={A.toast} /> },
    {
      key: "client",
      header: "Client",
      text: (g) => nameOr(g.appName, g.appId),
      cell: (g) => <span style={{ fontWeight: 600 }}>{nameOr(g.appName, g.appId)}</span>,
    },
    {
      key: "subject",
      header: "Subject",
      text: (g) => (g.subject ? nameOr(g.subjectName, g.subject) : "client_credentials"),
      cell: (g) => (g.subject ? nameOr(g.subjectName, g.subject) : <span className="badge gray">client_credentials</span>),
    },
    {
      key: "kind",
      header: "Kind",
      text: (g) => g.kind,
      cell: (g) => (
        <span className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
          {g.kind}
        </span>
      ),
    },
    {
      key: "login",
      header: "Login session",
      className: "hide-md mono",
      text: (g) => g.loginSessionId ?? "",
      cell: (g) => g.loginSessionId || "—",
    },
    {
      key: "expires",
      header: "Expires",
      className: "hide-md mono",
      sort: "expires",
      defaultDir: "desc",
      text: (g) => g.expires,
      cell: (g) => <Ts value={g.expires} />,
    },
  ];

  const tabs = <Seg options={["Login sessions", "OIDC grants"]} value={tab} onChange={setTab} />;

  return (
    <div className="fade-in">
      <PageHead
        page="sessions"
        sub="Durable SSO login sessions and the OIDC grants they fan out to. Terminating a session revokes its grants."
      />

      {isSessions ? (
        <DataTable
          id="sessions"
          list={sessions}
          columns={sessionColumns()}
          rowKey={(s) => s.id}
          onRowClick={(s) => setOpenId(s.id)}
          noun="session"
          empty="No login sessions match this filter."
          exportName="sessions"
          bulk={[terminateBulk(me)]}
          filters={
            <>
              {tabs}
              <SelectInput
                width={150}
                value={stateLabel}
                options={SESSION_STATES.map((s) => s.label)}
                onChange={(l) => sessions.setQuery({ state: SESSION_STATES.find((s) => s.label === l)?.value })}
              />
            </>
          }
        />
      ) : (
        <DataTable
          id="grants"
          list={grants}
          columns={grantColumns}
          rowKey={(g) => g.id}
          noun="grant"
          empty="No grants in scope."
          exportName="grants"
          filters={tabs}
        />
      )}

      {open && (
        <SessionDrawer
          session={open}
          // The owner's org rides on the row: a paged view has no users
          // collection to look it up in, and the gate cannot be guessed.
          canWrite={canWriteOrg(me, open.orgId, SESSION_WRITE_ROLES)}
          onClose={() => setOpenId(null)}
        />
      )}
    </div>
  );
}
