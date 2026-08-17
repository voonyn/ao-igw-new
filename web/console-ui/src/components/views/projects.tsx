"use client";

import { useId, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Icon } from "@/components/console/icons";
import { AppTypeBadge, Btn, confirmAction, EntityStateBadge, Field, KV, Pager, MonoChip, SelectInput, Toggle, Ts } from "@/components/console/primitives";
import { DataTable, type Column } from "@/components/console/data-table";
import { useTabParam } from "@/components/console/detail-route";
import { StateFilter } from "@/components/views/organizations";
import { EntityHeader, FullPage, ReadField, SectionCard, Tabs } from "@/components/console/overlays";
import { useConsole, usePagedList, usePending, type Actions } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { canWriteAnyOrg, canWriteOrg, pages, projectsApi } from "@/lib/console-api";
import { LABELS } from "@/lib/data";
import { orgName } from "@/lib/helpers";
import type { Project } from "@/lib/types";

// Project create/update/delete require ORG_OWNER or ORG_PROJECT_OWNER of the org.
const PROJECT_WRITE_ROLES = ["ORG_OWNER", "ORG_PROJECT_OWNER"];
const PROJECT_TABS = ["Settings", "Applications"];

export function ProjectDetailPage({
  project,
  A,
  canWrite,
  onClose,
  onChanged,
}: {
  project: Project;
  A: Actions;
  canWrite: boolean;
  onClose: () => void;
  /** Re-read this record from the server after a write (EH-6). */
  onChanged?: () => Promise<void>;
}) {
  const nameId = useId();
  const { accessibleOrgs } = useConsole();
  const [tab, setTab] = useTabParam(PROJECT_TABS);
  // The project's applications, paged. Narrowed to this project's ORGANIZATION
  // server-side and then to the project itself here: there is no projectId query
  // filter, and the org predicate already cuts the read down to a sibling set
  // small enough that *Load more* reaches the end.
  const appList = usePagedList(pages.apps, "applications", { orgId: project.orgId });
  const apps = appList.items.filter((a) => a.projectId === project.id && a.state !== 3);
  const PL = LABELS.privateLabeling;

  const [name, setName] = useState(project.name);
  const [roleAssertion, setRoleAssertion] = useState(project.roleAssertion);
  const [roleCheck, setRoleCheck] = useState(project.roleCheck);
  const [hasProjectCheck, setHasProjectCheck] = useState(project.hasProjectCheck);
  const [privateLabeling, setPrivateLabeling] = useState(project.privateLabeling);
  const [busy, runGuarded] = usePending();

  const dirty =
    name.trim() !== project.name ||
    roleAssertion !== project.roleAssertion ||
    roleCheck !== project.roleCheck ||
    hasProjectCheck !== project.hasProjectCheck ||
    privateLabeling !== project.privateLabeling;

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

  function save() {
    void run(() => projectsApi.update(project.id, { name: name.trim(), roleAssertion, roleCheck, hasProjectCheck, privateLabeling }), "Project saved");
  }

  async function remove() {
    const ok = await confirmAction({
      title: `Delete “${project.name}”?`,
      body: `The project is soft-deleted and disappears from the console together with its ${apps.length} application(s) — every client registered under it stops being manageable here. Records are retained in the database.`,
      confirmLabel: "Delete project",
      destructive: true,
    });
    if (!ok) return;
    await run(() => projectsApi.remove(project.id), "Deleted " + project.name, "ban", true);
  }

  function flag(on: boolean, setOn: (v: boolean) => void, label: string, desc: string) {
    return (
      <div className="kv">
        <span className="k" style={{ color: "var(--ink)", fontWeight: 500 }}>
          {label}
          <span style={{ display: "block", fontSize: 11.5, color: "var(--muted)", fontWeight: 400, marginTop: 2, maxWidth: 280 }}>{desc}</span>
        </span>
        <Toggle on={on} label={label} onChange={canWrite ? setOn : () => {}} />
      </div>
    );
  }

  return (
    <FullPage backLabel="Projects" crumb={project.name} onBack={onClose}>
      <EntityHeader
        tile={
          <span className="entity-tile">
            <Icon name="folder" size={26} />
          </span>
        }
        title={project.name}
        meta={
          <>
            <EntityStateBadge state={project.state} />
            <span>{orgName(accessibleOrgs, project.orgId)}</span>
            <span>
              Created <Ts value={project.created} />
            </span>
            <span>Project ID</span>
            <MonoChip value={project.id} toast={A.toast} />
          </>
        }
      />
      <Tabs tabs={PROJECT_TABS} value={tab} onChange={setTab} />

      {tab === "Settings" && (
        <div>
          <SectionCard title="Basic Information" desc="Core project record. A project groups applications under an owning organization.">
            {canWrite ? (
              <div>
                <label className="field-label" htmlFor={nameId}>
                  Name
                </label>
                <div style={{ display: "flex", gap: 8 }}>
                  <input id={nameId} className="text-input" value={name} onChange={(e) => setName(e.target.value)} />
                  <Btn className="btn ghost" pending={busy} disabled={!dirty || !name.trim()} onClick={save}>
                    Save
                  </Btn>
                </div>
              </div>
            ) : (
              <ReadField label="Name" value={project.name} />
            )}
            <ReadField label="Project ID" value={project.id} mono toast={A.toast} />
            <KV k="Organization" v={orgName(accessibleOrgs, project.orgId)} />
          </SectionCard>

          <SectionCard title="Authorization behaviour" desc="Not enforced yet. The gateway stores these three settings and reads none of them. Project roles and project grants do not exist here, so no sign-in is blocked and no token changes.">
            {flag(roleAssertion, setRoleAssertion, "Assert roles in tokens (not enforced yet)", "Intended to include the user’s project roles as claims in issued tokens.")}
            {flag(roleCheck, setRoleCheck, "Check role on authentication (not enforced yet)", "Intended to reject sign-in unless the user holds at least one project role.")}
            {flag(hasProjectCheck, setHasProjectCheck, "Require project grant (not enforced yet)", "Intended to admit only users of granted organizations to this project.")}
          </SectionCard>

          <SectionCard title="Private labeling" desc="Not enforced yet. The gateway stores this setting and reads it nowhere. Every user sees the tenant branding.">
            <SelectInput
              value={PL[privateLabeling]}
              options={Object.keys(PL).map((k) => PL[Number(k)])}
              onChange={(v) => canWrite && setPrivateLabeling(Number(Object.keys(PL).find((k) => PL[Number(k)] === v)))}
            />
          </SectionCard>

          {canWrite && project.state !== 3 && (
            <SectionCard danger title="Danger zone" desc="Deleting soft-deletes the project and hides it from the console. Records are retained.">
              <div>
                <Btn className="btn danger-ghost" pending={busy} onClick={remove}>
                  <Icon name="ban" size={15} />
                  Delete project
                </Btn>
              </div>
            </SectionCard>
          )}
        </div>
      )}

      {tab === "Applications" && (
        <SectionCard title={`Applications (${apps.length})`} desc="Applications registered in this project.">
          {apps.map((a) => (
            <div className="kv" key={a.id}>
              <span className="k" style={{ color: "var(--ink)", fontWeight: 500, display: "flex", alignItems: "center", gap: 8 }}>
                {a.name}
                <AppTypeBadge type={a.appType} />
              </span>
              <Link className="mono-chip" href={`/applications/${a.id}`}>
                open
                <Icon name="arrowR" size={11} />
              </Link>
            </div>
          ))}
          {!appList.loading && apps.length === 0 && (
            <div style={{ fontSize: 13, color: "var(--muted)" }}>No applications registered in this project.</div>
          )}
          <Pager list={appList} />
        </SectionCard>
      )}
    </FullPage>
  );
}

export function CreateProjectPage({ onClose }: { onClose: () => void }) {
  const orgFieldId = useId();
  const { me, accessibleOrgs } = useConsole();
  // The org picker reads `me.accessibleOrgs` — (id, name) pairs bounded by the
  // caller's own memberships, already loaded. No list request, no paging.
  const orgs = accessibleOrgs.filter((o) => canWriteOrg(me, o.id, PROJECT_WRITE_ROLES));
  const [name, setName] = useState("");
  const [orgNameSel, setOrgNameSel] = useState("");
  const [busy, run] = usePending();
  const org = orgs.find((o) => o.name === orgNameSel) ?? orgs[0];

  async function create() {
    if (!name.trim() || !org) return;
    const done = await run(
      () =>
        projectsApi.create({ orgId: org.id, name: name.trim(), roleAssertion: false, roleCheck: false, hasProjectCheck: false, privateLabeling: 0 }),
      { ok: "Created project " + name.trim() }
    );
    if (done) onClose();
  }

  return (
    <FullPage backLabel="Projects" crumb="New project" onBack={onClose}>
      <h1 className="entity-title" style={{ margin: "8px 0 4px" }}>
        New project
      </h1>
      <div className="entity-meta" style={{ marginBottom: 22 }}>
        Projects group applications under an owning organization.
      </div>
      <SectionCard title="Basic Information" desc="Authorization flags and private labeling can be configured after creation.">
        <div>
          <Field label="Name">
            <input className="text-input" placeholder="Customer Portal" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
        </div>
        <div>
          <label className="field-label" htmlFor={orgFieldId}>
            Organization
          </label>
          {orgs.length ? (
            <SelectInput id={orgFieldId} value={org?.name ?? ""} options={orgs.map((o) => o.name)} onChange={setOrgNameSel} />
          ) : (
            <div style={{ fontSize: 13, color: "var(--muted)" }}>No organization you can add projects to.</div>
          )}
        </div>
      </SectionCard>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" disabled={!name.trim() || !orgs.length} pending={busy} onClick={create}>
          Create project
        </Btn>
      </div>
    </FullPage>
  );
}

export function ProjectsView() {
  const { me, accessibleOrgs } = useConsole();
  const router = useRouter();
  const canCreate = canWriteAnyOrg(me, PROJECT_WRITE_ROLES);
  const list = usePagedList(pages.projects, "projects", { urlSync: true });

  // The "Apps" column is gone: counting a different collection per row is a
  // request per row once each view holds a page. The project's own detail page
  // lists its applications.
  const columns: Column<Project>[] = [
    {
      key: "name",
      header: "Project",
      sort: "name",
      fixed: true,
      text: (p) => p.name,
      cell: (p) => <span style={{ fontWeight: 600 }}>{p.name}</span>,
    },
    {
      key: "org",
      header: "Organization",
      text: (p) => orgName(accessibleOrgs, p.orgId),
      cell: (p) => orgName(accessibleOrgs, p.orgId),
    },
    {
      key: "flags",
      header: "Authorization flags (not enforced yet)",
      className: "hide-md",
      text: (p) =>
        [p.roleAssertion && "assert roles", p.roleCheck && "role check", p.hasProjectCheck && "project grant"]
          .filter(Boolean)
          .join(" / "),
      cell: (p) => (
        <span className="chip-row">
          {p.roleAssertion && <span className="chip">assert roles</span>}
          {p.roleCheck && <span className="chip">role check</span>}
          {p.hasProjectCheck && <span className="chip">project grant</span>}
          {!p.roleAssertion && !p.roleCheck && !p.hasProjectCheck && (
            <span style={{ color: "var(--muted-2)", fontSize: 12.5 }}>none</span>
          )}
        </span>
      ),
    },
    {
      key: "state",
      header: "State",
      sort: "state",
      text: (p) => LABELS.entityState[p.state] ?? String(p.state),
      cell: (p) => <EntityStateBadge state={p.state} />,
    },
    {
      key: "created",
      header: "Created",
      className: "hide-md mono",
      sort: "created",
      defaultDir: "desc",
      text: (p) => p.created,
      cell: (p) => <Ts value={p.created} />,
    },
  ];

  return (
    <div className="fade-in">
      <PageHead
        page="projects"
        sub="A project groups applications and defines how roles are asserted and enforced at token issue."
        actions={
          canCreate && (
            <>
              <Link className="btn primary" href="/projects/new">
                <Icon name="plus" size={15} sw={2.2} />
                New project
              </Link>
            </>
          )
        }
      />

      <DataTable
        id="projects"
        list={list}
        columns={columns}
        rowKey={(p) => p.id}
        onRowClick={(p) => router.push(`/projects/${p.id}`)}
        noun="project"
        empty="No projects match this filter."
        exportName="projects"
        search={{ fields: "the project name", placeholder: "Search projects…" }}
        filters={<StateFilter list={list} />}
      />
    </div>
  );
}
