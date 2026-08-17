"use client";

import { useEffect, useId, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Icon } from "@/components/console/icons";
import { Avatar, Btn, confirmAction, EntityStateBadge, Field, KV, Pager, MonoChip, SelectInput, Ts } from "@/components/console/primitives";
import { DataTable, type Column } from "@/components/console/data-table";
import { useTabParam } from "@/components/console/detail-route";
import { EntityHeader, FullPage, ReadField, SectionCard, Tabs } from "@/components/console/overlays";
import { useConsole, usePagedList, usePending, type Actions } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { EntityAuditTab } from "./audit";
import { sessionColumns, terminateBulk } from "./sessions";
import { canManageTenant, getTotal, orgsApi, pages } from "@/lib/console-api";
import { LABELS } from "@/lib/data";
import { initials, nameOr } from "@/lib/helpers";
import type { Org } from "@/lib/types";

// Org rename/delete require ORG_OWNER of that org (or an tenant manager) —
// the detail route resolves that and passes `canWrite` in.
// Sessions and Audit fell out of the per-user work: the sessions read already
// narrows by `orgId`, and `audit_events.entity_id` is indexed — so both are the
// existing reader under an existing predicate, not a new surface.
const ORG_TABS = ["Settings", "Projects & Users", "Members", "Sessions", "Audit"];

/** One organization's user count, read as a scoped total. The users tab only
 * ever rendered a number, so counting server-side beats fetching rows to measure. */
function useOrgUserCount(orgId: string): number | null {
  const { dataVersion } = useConsole();
  const [n, setN] = useState<number | null>(null);
  useEffect(() => {
    let cancelled = false;
    getTotal("/api/admin/users", { orgId })
      .then((v) => !cancelled && setN(v))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [orgId, dataVersion]);
  return n;
}

export function OrgDetailPage({
  org,
  A,
  canWrite,
  onClose,
  onChanged,
}: {
  org: Org;
  A: Actions;
  canWrite: boolean;
  onClose: () => void;
  /** Re-read this record from the server after a write (EH-6). */
  onChanged?: () => Promise<void>;
}) {
  const nameId = useId();
  const [tab, setTab] = useTabParam(ORG_TABS);
  const [name, setName] = useState(org.name);
  const [busy, runGuarded] = usePending();
  // Each child collection is read narrowed to THIS organization, not filtered out
  // of a tenant-wide store. `userCount` is a scoped total (one counted request):
  // the users tab only ever showed a number, so there is no reason to fetch rows.
  const projectList = usePagedList(pages.projects, "projects", { orgId: org.id });
  const memberList = usePagedList(pages.orgMembers, "members", { orgId: org.id });
  const projects = projectList.items.filter((p) => p.state !== 3);
  const members = memberList.items;
  const userCount = useOrgUserCount(org.id);

  async function run(fn: () => Promise<unknown>, ok: string, okIcon?: string, close?: boolean) {
    const done = await runGuarded(fn, {
      ok,
      icon: okIcon,
      after: async () => {
        await A.reload();
        if (!close && onChanged) await onChanged();
      },
    });
    if (done && close) onClose();
  }

  async function remove() {
    const ok = await confirmAction({
      title: `Delete “${org.name}”?`,
      body: `The organization is soft-deleted and disappears from the console, together with its projects, users, and organization memberships as far as this console is concerned. Records are retained in the database, but nothing here will show them again.`,
      confirmLabel: "Delete organization",
      destructive: true,
    });
    if (!ok) return;
    await run(() => orgsApi.remove(org.id), "Deleted " + org.name, "ban", true);
  }

  return (
    <FullPage backLabel="Organizations" crumb={org.name} onBack={onClose}>
      <EntityHeader
        tile={
          <span className="entity-tile" style={{ background: "var(--accent)", border: "none", color: "#fff", fontWeight: 700, fontSize: 19 }}>
            {initials(org.name)}
          </span>
        }
        title={org.name}
        meta={
          <>
            <EntityStateBadge state={org.state} />
            {org.isDefault && <span className="badge gray">tenant default org</span>}
            <span>
              Created <Ts value={org.created} />
            </span>
            <span>Org ID</span>
            <MonoChip value={org.id} toast={A.toast} />
          </>
        }
      />
      <Tabs tabs={ORG_TABS} value={tab} onChange={setTab} />

      {tab === "Settings" && (
        <div>
          <SectionCard title="Basic Information" desc="Core organization record. Users always belong to exactly one organization.">
            {canWrite ? (
              <div>
                <label className="field-label" htmlFor={nameId}>
                  Name
                </label>
                <div style={{ display: "flex", gap: 8 }}>
                  <input id={nameId} className="text-input" value={name} onChange={(e) => setName(e.target.value)} />
                  <Btn
                    className="btn ghost"
                    pending={busy}
                    disabled={!name.trim() || name.trim() === org.name}
                    onClick={() => run(() => orgsApi.update(org.id, { name: name.trim() }), "Renamed organization")}
                  >
                    Save
                  </Btn>
                </div>
              </div>
            ) : (
              <ReadField label="Name" value={org.name} />
            )}
            <ReadField label="Organization ID" value={org.id} mono toast={A.toast} />
            <KV k="Created" v={<Ts value={org.created} />} />
          </SectionCard>

          {canWrite && org.state !== 3 && (
            <SectionCard danger title="Danger zone" desc="Deleting soft-deletes the organization and hides it from the console. Records are retained.">
              <div>
                <Btn className="btn danger-ghost" pending={busy} onClick={remove}>
                  <Icon name="ban" size={15} />
                  Delete organization
                </Btn>
              </div>
            </SectionCard>
          )}
        </div>
      )}

      {tab === "Projects & Users" && (
        <div>
          <SectionCard title={`Projects (${projects.length})`} desc="Projects owned by this organization group its applications.">
            {projects.map((p) => (
              <div className="kv" key={p.id}>
                <span className="k" style={{ color: "var(--ink)", fontWeight: 500 }}>
                  {p.name}
                </span>
                <button type="button" className="mono-chip" onClick={() => A.nav("projects")}>
                  open
                  <Icon name="arrowR" size={11} />
                </button>
              </div>
            ))}
            {!projectList.loading && projects.length === 0 && (
              <div style={{ fontSize: 13, color: "var(--muted)" }}>No projects in this organization.</div>
            )}
            <Pager list={projectList} />
          </SectionCard>
          <SectionCard title={`Users (${userCount ?? "…"})`} desc="Identities whose home organization is this one.">
            <div style={{ fontSize: 13, color: "var(--muted)" }}>
              {userCount ?? 0} user{userCount === 1 ? "" : "s"} belong to this org.&nbsp;
              <button type="button" className="mono-chip" onClick={() => A.nav("users")}>
                view users
                <Icon name="arrowR" size={11} />
              </button>
            </div>
          </SectionCard>
        </div>
      )}

      {tab === "Members" && (
        <SectionCard title={`Members (${members.length})`} desc="Users holding organization-level role grants. Manage grants under Members & Roles.">
          {members.map((m) => {
            const who = nameOr(m.userName, m.userId);
            return (
              <div className="kv" key={m.userId}>
                <span className="k" style={{ color: "var(--ink)", fontWeight: 500, display: "flex", alignItems: "center", gap: 8 }}>
                  <Avatar name={who} size={22} />
                  {who}
                </span>
                <span className="v" style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                  {m.roles.map((r) => (
                    <span key={r} className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                      {r}
                    </span>
                  ))}
                </span>
              </div>
            );
          })}
          {members.length === 0 && <div style={{ fontSize: 13, color: "var(--muted)" }}>No organization members yet.</div>}
        </SectionCard>
      )}

      {/* Both tabs mount their read only while open — an organization's sessions
          are unbounded, so fetching them to render a tab nobody opened would
          cost a page load per detail view. */}
      {tab === "Sessions" && <OrgSessionsTab org={org} />}

      {tab === "Audit" && <EntityAuditTab entityId={org.id} noun="organization" />}
    </FullPage>
  );
}

/** Login sessions belonging to this organization — the tenant-wide Sessions read
 * narrowed by `orgId`, with the same columns and the same bulk terminate. */
function OrgSessionsTab({ org }: { org: Org }) {
  const { me } = useConsole();
  const list = usePagedList(pages.sessions, "sessions", { orgId: org.id });
  return (
    <SectionCard title="Login sessions" desc="Every SSO session held by a member of this organization, active and signed out. Revoking a session revokes its token grants — refresh tokens included — and deletes the record.">
      <DataTable
        id="org-sessions"
        list={list}
        columns={sessionColumns()}
        rowKey={(s) => s.id}
        noun="session"
        empty="No login sessions in this organization."
        bulk={[terminateBulk(me)]}
      />
    </SectionCard>
  );
}

export function CreateOrgPage({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState("");
  const [busy, run] = usePending();

  async function create() {
    if (!name.trim()) return;
    if (await run(() => orgsApi.create({ name: name.trim() }), { ok: "Created organization " + name.trim() })) onClose();
  }

  return (
    <FullPage backLabel="Organizations" crumb="New organization" onBack={onClose}>
      <h1 className="entity-title" style={{ margin: "8px 0 4px" }}>
        New organization
      </h1>
      <div className="entity-meta" style={{ marginBottom: 22 }}>
        Organizations partition this tenant; each user belongs to exactly one.
      </div>
      <SectionCard title="Basic Information" desc="Give the organization a name. Domains can be attached afterwards from its Domains tab.">
        <div>
          <Field label="Name">
            <input className="text-input" placeholder="Acme Engineering" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
        </div>
      </SectionCard>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" disabled={!name.trim()} pending={busy} onClick={create}>
          Create organization
        </Btn>
      </div>
    </FullPage>
  );
}

/** The entity-state filter every soft-deletable resource offers. An absent state
 * excludes removed rows server-side, so "Deleted" is how a caller asks to see
 * them — the console used to hide them client-side while `total` counted them. */
export const ENTITY_STATES: { label: string; value?: number }[] = [
  { label: "All states" },
  { label: "Active", value: 1 },
  { label: "Inactive", value: 2 },
  { label: "Deleted", value: 3 },
];

/** The state `<select>` shared by the organizations, projects, and applications
 * tables — same enum, same wording, one place to change it. */
export function StateFilter({ list }: { list: { query: { state?: number }; setQuery: (p: { state?: number }) => void } }) {
  const label = ENTITY_STATES.find((s) => s.value === list.query.state)?.label ?? "All states";
  return (
    <SelectInput
      width={140}
      value={label}
      options={ENTITY_STATES.map((s) => s.label)}
      onChange={(l) => list.setQuery({ state: ENTITY_STATES.find((s) => s.label === l)?.value })}
    />
  );
}

export function OrganizationsView() {
  const { me } = useConsole();
  const router = useRouter();
  const canCreate = canManageTenant(me);
  const list = usePagedList(pages.orgs, "organizations", { urlSync: true });

  const columns: Column<Org>[] = [
    {
      key: "name",
      header: "Organization",
      sort: "name",
      fixed: true,
      text: (o) => o.name,
      cell: (o) => (
        <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="org-tile" style={{ width: 28, height: 28, borderRadius: 8, background: "var(--accent-soft)", color: "var(--accent-deep)", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 11 }}>
            {initials(o.name)}
          </span>
          <span style={{ fontWeight: 600 }}>
            {o.name}
            {o.isDefault && (
              <span className="badge gray" style={{ marginLeft: 8 }}>
                default
              </span>
            )}
          </span>
        </span>
      ),
    },
    // The per-row "Projects"/"Users" counts are gone: counting a different
    // collection per row is a request per row once a view holds a page. The
    // org's own detail page carries both.
    {
      key: "state",
      header: "State",
      sort: "state",
      text: (o) => LABELS.entityState[o.state] ?? String(o.state),
      cell: (o) => <EntityStateBadge state={o.state} />,
    },
    {
      key: "created",
      header: "Created",
      className: "hide-md mono",
      sort: "created",
      defaultDir: "desc",
      text: (o) => o.created,
      cell: (o) => <Ts value={o.created} />,
    },
  ];

  return (
    <div className="fade-in">
      <PageHead
        page="orgs"
        sub="Organizations partition this tenant. Users always belong to exactly one organization."
        actions={
          canCreate && (
            <>
              <Link className="btn primary" href="/organizations/new">
                <Icon name="plus" size={15} sw={2.2} />
                New organization
              </Link>
            </>
          )
        }
      />

      <DataTable
        id="organizations"
        list={list}
        columns={columns}
        rowKey={(o) => o.id}
        onRowClick={(o) => router.push(`/organizations/${o.id}`)}
        noun="organization"
        empty="No organizations match this filter."
        exportName="organizations"
        search={{ fields: "the organization name", placeholder: "Search organizations…" }}
        filters={<StateFilter list={list} />}
      />
    </div>
  );
}
