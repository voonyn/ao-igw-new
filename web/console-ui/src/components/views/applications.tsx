"use client";

import { useId, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Icon } from "@/components/console/icons";
import { AppTypeBadge, Btn, confirmAction, EntityStateBadge, Field, KV, MonoChip, OptChip, PickerTruncated, ProtoBanner, Seg, SelectInput, Toggle, Ts } from "@/components/console/primitives";
import { DataTable, type Column } from "@/components/console/data-table";
import { useTabParam } from "@/components/console/detail-route";
import { PageHead } from "@/components/console/page-head";
import { EntityAuditTab } from "@/components/views/audit";
import { StateFilter } from "@/components/views/organizations";
import { EntityHeader, FullPage, ReadField, SectionCard, Tabs } from "@/components/console/overlays";
import { useConsole, usePagedList, usePending, type Actions } from "@/components/console/store";
import { appsApi, canWriteAnyOrg, canWriteOrg, pages, type AppOidcBody } from "@/lib/console-api";
import { AUTHN_METHODS, GRANT_TYPES, LABELS, RESPONSE_TYPES } from "@/lib/data";
import { nameOr } from "@/lib/helpers";
import type { App, App as AppType } from "@/lib/types";

// App create/update/delete require ORG_OWNER or ORG_PROJECT_OWNER of the app's org
// (resolved via its project). The gateway re-checks; this only gates affordances.
const APP_WRITE_ROLES = ["ORG_OWNER", "ORG_PROJECT_OWNER"];

// Loopback hosts an OAuth client legitimately needs over plain http during
// development. Everything else must be https.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/**
 * Rejects a redirect / post-logout URI the provider would refuse, with the
 * reason. `new URL()` is the platform's own parser — a hand-rolled pattern gets
 * the interesting cases wrong. Returns null when the entry is acceptable.
 */
export function uriProblem(raw: string, existing: string[]): string | null {
  const v = raw.trim();
  if (!v) return "Enter a URI.";
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return "Not an absolute URL — include the scheme, e.g. https://app.example.com/callback.";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return `Unsupported scheme “${u.protocol}” — use https.`;
  if (u.protocol === "http:" && !LOOPBACK_HOSTS.has(u.hostname))
    return "Plain http is only allowed for localhost — use https for any other host.";
  if (u.hash) return "A redirect URI must not carry a fragment.";
  const normalized = u.toString();
  if (existing.some((e) => normalizeUri(e) === normalized)) return "Already registered on this client.";
  return null;
}

function normalizeUri(raw: string): string {
  try {
    return new URL(raw.trim()).toString();
  } catch {
    return raw.trim();
  }
}

function UriListEditor({
  uris,
  placeholder,
  readOnly,
  onChange,
}: {
  uris: string[];
  placeholder: string;
  readOnly?: boolean;
  onChange: (next: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  function add() {
    const problem = uriProblem(draft, uris);
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    onChange(uris.concat([normalizeUri(draft)]));
    setDraft("");
  }
  return (
    <div>
      <div className="uri-list">
        {uris.map((u, i) => (
          <div className="uri-row" key={u + i}>
            <span className="uri" title={u}>
              {u}
            </span>
            {!readOnly && (
              <button type="button" className="rm" aria-label={"Remove " + u} onClick={() => onChange(uris.filter((_, j) => j !== i))}>
                <Icon name="x" size={14} />
              </button>
            )}
          </div>
        ))}
        {uris.length === 0 && <div style={{ fontSize: 13, color: "var(--muted)" }}>None registered.</div>}
      </div>
      {!readOnly && (
        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
          <input
            className="text-input"
            style={{ height: 36, fontFamily: "var(--font-mono)", fontSize: 12 }}
            placeholder={placeholder}
            value={draft}
            aria-invalid={!!error}
            onChange={(e) => {
              setDraft(e.target.value);
              if (error) setError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") add();
            }}
          />
          <button type="button" className="btn sm ghost" style={{ height: 36 }} onClick={add}>
            <Icon name="plus" size={14} />
            Add
          </button>
        </div>
      )}
      {error && (
        <div style={{ marginTop: 6, fontSize: 12.5, color: "var(--error)", display: "flex", alignItems: "center", gap: 6 }}>
          <Icon name="alert" size={13} sw={2.2} />
          {error}
        </div>
      )}
    </div>
  );
}

function FutureKVGroup({ title, data, emptyText }: { title: string; data: Record<string, string> | null; emptyText?: string }) {
  return (
    <SectionCard title={title}>
      {data ? (
        Object.keys(data).map((k) => <KV key={k} k={k} v={<span style={{ color: "var(--muted)" }}>{data[k]}</span>} />)
      ) : (
        <div style={{ fontSize: 13, color: "var(--muted)" }}>{emptyText}</div>
      )}
    </SectionCard>
  );
}

export function AppDetailPage({
  app,
  A,
  canWrite,
  onClose,
  onChanged,
}: {
  app: App;
  A: Actions;
  canWrite: boolean;
  onClose: () => void;
  /** Re-read this record from the server after a write (EH-6). */
  onChanged?: () => Promise<void>;
}) {
  const oidc = app.oidc;
  const isPublic = oidc?.authnMethod === "none";

  const TABS = ["Settings"];
  if (oidc && app.appType === 1) TABS.push("URIs");
  if (oidc) TABS.push("Grants & Scopes", "Advanced");
  // Audit only. There is no session or grant predicate by application — the
  // sessions read narrows by subject and organization, not by client — so a
  // Sessions tab here would need a new server-side filter. Not forced.
  TABS.push("Audit");

  const [tab, setTab] = useTabParam(TABS);
  const [name, setName] = useState(app.name);
  const [authnMethod, setAuthnMethod] = useState(oidc?.authnMethod ?? "client_secret_basic");
  const [subjectType, setSubjectType] = useState(oidc?.subjectType || "public");
  const [parRequired, setParRequired] = useState(!!oidc?.parRequired);
  const [redirectUris, setRedirectUris] = useState<string[]>(oidc?.redirectUris ?? []);
  const [postLogoutUris, setPostLogoutUris] = useState<string[]>(oidc?.postLogoutUris ?? []);
  const [grantTypes, setGrantTypes] = useState<string[]>(oidc?.grantTypes ?? []);
  const [responseTypes, setResponseTypes] = useState<string[]>(oidc?.responseTypes ?? []);
  const [busy, runGuarded] = usePending();
  // The rotated secret is returned exactly once — hold it until the operator
  // navigates away, because there is no second chance to read it.
  const [freshSecret, setFreshSecret] = useState<string | null>(null);

  function toggleList(list: string[], set: (v: string[]) => void, value: string) {
    if (!canWrite) return;
    set(list.includes(value) ? list.filter((x) => x !== value) : list.concat([value]));
  }

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
      title: `Delete “${app.name}”?`,
      body: "The application is soft-deleted: the client can no longer authenticate, every sign-in and token request against it fails immediately, and any integration using it breaks. Records are retained in the database.",
      confirmLabel: "Delete application",
      destructive: true,
    });
    if (!ok) return;
    await run(() => appsApi.remove(app.id), "Deleted " + app.name, "ban", true);
  }

  // BL-1: rotation is irreversible and breaks a live integration the moment it
  // lands, so it ships behind a confirmation naming exactly that consequence.
  async function rotate() {
    const confirmed = await confirmAction({
      title: `Rotate the client secret for “${app.name}”?`,
      body: "The previous secret stops working immediately — every deployment still holding it fails to authenticate until it is updated. The new secret is shown once and cannot be retrieved again.",
      confirmLabel: "Rotate secret",
      destructive: true,
    });
    if (!confirmed) return;
    await runGuarded(
      async () => {
        const res = await appsApi.rotateSecret(app.id);
        setFreshSecret(res.secret);
      },
      {
        ok: "Client secret rotated — copy it now, it is shown once",
        icon: "key",
        after: async () => {
          await A.reload();
          if (onChanged) await onChanged();
        },
      }
    );
  }

  function save() {
    const body = oidc
      ? ({
          clientId: oidc.clientId,
          tokenAuthnMethod: authnMethod,
          subjectType,
          parRequired,
          redirectUris,
          postLogoutUris,
          grantTypes,
          responseTypes,
          scopeIds: oidc.scopeIds,
        } as AppOidcBody)
      : null;
    run(() => appsApi.update(app.id, { name: name.trim(), oidc: body }), "Application saved");
  }

  return (
    <FullPage backLabel="Applications" crumb={app.name} onBack={onClose}>
      <EntityHeader
        tile={
          <span className="entity-tile">
            <Icon name="apps" size={26} />
          </span>
        }
        title={app.name}
        meta={
          <>
            <AppTypeBadge type={app.appType} />
            <EntityStateBadge state={app.state} />
            <span>{nameOr(app.projectName, app.projectId)}</span>
            {oidc && (
              <>
                <span>Client ID</span>
                <MonoChip value={oidc.clientId} toast={A.toast} />
              </>
            )}
          </>
        }
        actions={
          canWrite ? (
            <Btn className="btn primary" pending={busy} disabled={!name.trim()} onClick={save}>
              Save changes
            </Btn>
          ) : undefined
        }
      />
      <Tabs tabs={TABS} value={tab} onChange={setTab} />

      {tab === "Settings" && (
        <div>
          {app.appType === 2 && (
            <ProtoBanner>
              SAML applications are reserved in the schema (<span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>app_type=2</span>) but the protocol is not implemented yet. This entry is a placeholder — configuration will arrive with SAML support.
            </ProtoBanner>
          )}

          <SectionCard title="Basic Information" desc="Core application record and its issued OIDC client credentials.">
            {canWrite ? (
              <div>
                <Field label="Name">
                  <input className="text-input" value={name} onChange={(e) => setName(e.target.value)} />
                </Field>
              </div>
            ) : (
              <ReadField label="Name" value={app.name} />
            )}
            {oidc && <ReadField label="Client ID" value={oidc.clientId} mono toast={A.toast} />}
            {oidc &&
              (isPublic ? (
                <KV k="Client secret" v={<span className="badge gray">None — public client</span>} />
              ) : (
                <KV
                  k="Client secret"
                  v={
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--muted)" }}>{oidc.secretSet ? "••••••••••••••••" : "not set"}</span>
                      {canWrite && (
                        <Btn className="btn sm ghost" pending={busy} onClick={rotate}>
                          <Icon name="refresh" size={13} />
                          Rotate
                        </Btn>
                      )}
                    </span>
                  }
                />
              ))}
            {freshSecret && (
              <ReadField
                label="New client secret — shown once"
                value={freshSecret}
                mono
                secret
                toast={A.toast}
                extra={<span className="badge amber">copy it now</span>}
              />
            )}
            {oidc?.secretExpires && <KV k="Secret expires" v={<Ts value={oidc.secretExpires} />} />}
            <KV k="Created" v={<Ts value={app.created} />} />
          </SectionCard>

          {oidc && (
            <SectionCard title="Authentication" desc="How this client authenticates to the token endpoint and how its subject identifiers are derived.">
              <div className="form-grid">
                <div className="full">
                  <Field label="Token endpoint authn method">
                    <SelectInput value={authnMethod} options={AUTHN_METHODS} onChange={(v) => canWrite && setAuthnMethod(v)} />
                  </Field>
                </div>
                <div>
                  <Field label="Subject type">
                    <SelectInput value={subjectType} options={["public", "pairwise"]} onChange={(v) => canWrite && setSubjectType(v)} />
                  </Field>
                </div>
                <div>
                  <Field label="Default max age (secs)">
                    <input className="text-input" type="number" readOnly value={oidc.defaultMaxAge == null ? "" : oidc.defaultMaxAge} placeholder="none" title="Not editable via the admin API yet" />
                  </Field>
                </div>
              </div>
              <div className="kv" style={{ marginTop: 6 }}>
                <span className="k" style={{ color: "var(--ink)", fontWeight: 500 }}>
                  Require pushed authorization requests (PAR)
                  <span style={{ display: "block", fontSize: 11.5, color: "var(--muted)", fontWeight: 400, marginTop: 2 }}>Authorization requests must arrive via the PAR endpoint.</span>
                </span>
                <Toggle on={parRequired} label="PAR required" onChange={(v) => canWrite && setParRequired(v)} />
              </div>
              <div className="kv" style={{ marginTop: 6 }}>
                <span className="k" style={{ color: "var(--ink)", fontWeight: 500 }}>
                  First-party client
                  <span style={{ display: "block", fontSize: 11.5, color: "var(--muted)", fontWeight: 400, marginTop: 2 }}>
                    Skips the consent screen for every user of this client, including when the relying party sends <code>prompt=consent</code>, and the client cannot be revoked from the user&apos;s connected-apps list. Not editable
                    from the console.
                  </span>
                </span>
                <span className={oidc.isFirstParty ? "badge amber" : "badge"}>{oidc.isFirstParty ? "first-party" : "no"}</span>
              </div>
            </SectionCard>
          )}

          {canWrite && app.state !== 3 && (
            <SectionCard danger title="Danger zone" desc="Deleting soft-deletes the application; it can no longer authenticate.">
              <div>
                <Btn className="btn danger-ghost" pending={busy} onClick={remove}>
                  <Icon name="ban" size={15} />
                  Delete application
                </Btn>
              </div>
            </SectionCard>
          )}
        </div>
      )}

      {tab === "URIs" && oidc && (
        <div>
          <SectionCard title="Redirect URIs" desc="Allowed callback URIs after authorization. Exact-match, HTTPS in production.">
            <UriListEditor uris={redirectUris} placeholder="https://app.example.com/callback" readOnly={!canWrite} onChange={setRedirectUris} />
          </SectionCard>
          <SectionCard title="Post-logout redirect URIs" desc="Allowed URIs to return the user to after RP-initiated logout.">
            <UriListEditor uris={postLogoutUris} placeholder="https://app.example.com/signed-out" readOnly={!canWrite} onChange={setPostLogoutUris} />
          </SectionCard>
        </div>
      )}

      {tab === "Grants & Scopes" && oidc && (
        <div>
          <SectionCard title="Grant types" desc="OAuth 2.0 grant types this client may use at the token endpoint.">
            <div className="chip-row">
              {GRANT_TYPES.map((g) => (
                <OptChip key={g} label={g} on={grantTypes.includes(g)} onChange={() => toggleList(grantTypes, setGrantTypes, g)} />
              ))}
            </div>
          </SectionCard>
          <SectionCard title="Response types" desc="Response types permitted at the authorization endpoint.">
            <div className="chip-row">
              {RESPONSE_TYPES.map((r) => (
                <OptChip key={r} label={r} on={responseTypes.includes(r)} onChange={() => toggleList(responseTypes, setResponseTypes, r)} />
              ))}
            </div>
          </SectionCard>
          <SectionCard title="Scopes" desc="Scopes this client is allowed to request.">
            <div className="chip-row">
              {oidc.scopeIds.map((s) => (
                <span key={s} className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
                  {s}
                </span>
              ))}
            </div>
          </SectionCard>
        </div>
      )}

      {tab === "Advanced" && oidc && (
        <div>
          <FutureKVGroup title="Signing & encryption" data={oidc.crypto} />
          <FutureKVGroup title="Per-endpoint authn" data={oidc.authn} />
          <FutureKVGroup title="Token binding (DPoP / mTLS)" data={oidc.binding} />
          <FutureKVGroup title="CIBA backchannel" data={oidc.ciba} emptyText="Not configured. Backchannel authentication ships in a later release." />
          <FutureKVGroup title="OpenID Federation" data={oidc.federation} emptyText="Not configured. Trust-anchor federation ships in a later release." />
        </div>
      )}

      {tab === "Audit" && <EntityAuditTab entityId={app.id} noun="application" />}

    </FullPage>
  );
}

export function CreateAppPage({ onClose }: { onClose: () => void }) {
  const projectId = useId();
  const { me } = useConsole();
  // ponytail: the project picker follows the cursor to exhaustion under a page
  // bound rather than offering a *Load more* nobody can reach inside a <select>,
  // and says so when the bound cuts the list short. Swap in a typeahead over a
  // filtered read if a tenant ever outgrows it.
  const projectPage = usePagedList(pages.projects, "projects", { picker: true });
  const projects = projectPage.items.filter((p) => p.state === 1 && canWriteOrg(me, p.orgId, APP_WRITE_ROLES));
  const [name, setName] = useState("");
  const [projName, setProjName] = useState("");
  const [type, setType] = useState("OIDC");
  const [busy, run] = usePending();
  // Resolve against the loaded page rather than seeding state from it: the list
  // arrives after first render, so a seeded default would always be empty.
  const proj = projects.find((p) => p.name === projName) ?? projects[0];

  async function create() {
    if (!name.trim() || !proj) return;
    const appType: 1 | 2 | 3 = type === "OIDC" ? 1 : type === "SAML" ? 2 : 3;
    const oidc: AppOidcBody | null =
      appType === 2
        ? null
        : {
            // client_id is public by design, so the exposure here is collision,
            // not predictability — the platform UUID closes it in one call.
            clientId: crypto.randomUUID(),
            tokenAuthnMethod: appType === 3 ? "private_key_jwt" : "client_secret_basic",
            subjectType: "public",
            parRequired: false,
            redirectUris: [],
            postLogoutUris: [],
            grantTypes: appType === 3 ? ["client_credentials"] : ["authorization_code"],
            responseTypes: appType === 3 ? [] : ["code"],
            scopeIds: ["openid", "profile", "email"],
          };
    const done = await run(() => appsApi.create({ projectId: proj.id, name: name.trim(), appType, oidc }), {
      ok: "Registered " + name.trim() + (appType !== 2 ? " — rotate a client secret to activate it" : ""),
      icon: "key",
    });
    if (done) onClose();
  }

  return (
    <FullPage backLabel="Applications" crumb="Register application" onBack={onClose}>
      <h1 className="entity-title" style={{ margin: "8px 0 4px" }}>
        Register application
      </h1>
      <div className="entity-meta" style={{ marginBottom: 22 }}>
        OIDC clients receive credentials on creation; redirect URIs and grants are configured next.
      </div>
      <SectionCard title="Basic Information" desc="Name the application and choose the project and protocol it belongs to.">
        <div>
          <Field label="Name">
            <input className="text-input" placeholder="Customer Portal SPA" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
        </div>
        <div>
          <label className="field-label" htmlFor={projectId}>
            Project
          </label>
          {projects.length ? (
            <>
              <SelectInput id={projectId} value={proj?.name ?? ""} options={projects.map((p) => p.name)} onChange={setProjName} />
              {projectPage.truncated && <PickerTruncated what="projects" />}
            </>
          ) : (
            <div style={{ fontSize: 13, color: "var(--muted)" }}>
              {projectPage.loading ? "Loading projects…" : "No project you can register applications in."}
            </div>
          )}
        </div>
        <div>
          <span className="field-label">Type</span>
          <Seg options={["OIDC", "SAML", "API"]} value={type} onChange={setType} label="Application type" />
          {type === "SAML" && (
            <div style={{ marginTop: 8, fontSize: 12.5, color: "var(--warn)", display: "flex", alignItems: "center", gap: 6 }}>
              <Icon name="alert" size={13} sw={2.2} />
              SAML is reserved in the schema but not functional yet.
            </div>
          )}
        </div>
      </SectionCard>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" disabled={!name.trim() || !projects.length} pending={busy} onClick={create}>
          Register
        </Btn>
      </div>
    </FullPage>
  );
}

export function ApplicationsView() {
  const { me, A } = useConsole();
  const router = useRouter();
  const canCreate = canWriteAnyOrg(me, APP_WRITE_ROLES);
  const list = usePagedList(pages.apps, "applications", { urlSync: true });

  // The application-type segment is gone rather than kept client-side. It never
  // reached the query, so on a tenant with more applications than one page it
  // hid rows it could not see — and `applications` offers no server-side type
  // filter to replace it with (created/name/state are the whole allowlist).
  // Type stays a column; when a type filter is asked for it arrives with its
  // index, like every other key here.
  const columns: Column<AppType>[] = [
    {
      key: "name",
      header: "Application",
      sort: "name",
      fixed: true,
      text: (a) => a.name,
      cell: (a) => <span style={{ fontWeight: 600 }}>{a.name}</span>,
    },
    {
      key: "project",
      header: "Project",
      text: (a) => nameOr(a.projectName, a.projectId),
      cell: (a) => nameOr(a.projectName, a.projectId),
    },
    {
      key: "type",
      header: "Type",
      text: (a) => LABELS.appType[a.appType] ?? String(a.appType),
      cell: (a) => <AppTypeBadge type={a.appType} />,
    },
    {
      key: "clientId",
      header: "Client ID",
      className: "hide-md",
      text: (a) => a.oidc?.clientId ?? "",
      cell: (a) => (a.oidc ? <MonoChip value={a.oidc.clientId} short toast={A.toast} /> : <span className="mono">—</span>),
    },
    {
      key: "authn",
      header: "Authn method",
      className: "hide-md mono",
      text: (a) => a.oidc?.authnMethod ?? "",
      cell: (a) => a.oidc?.authnMethod ?? "—",
    },
    {
      key: "state",
      header: "State",
      sort: "state",
      text: (a) => LABELS.entityState[a.state] ?? String(a.state),
      cell: (a) => <EntityStateBadge state={a.state} />,
    },
    {
      key: "created",
      header: "Created",
      className: "hide-md mono",
      sort: "created",
      defaultDir: "desc",
      text: (a) => a.created,
      cell: (a) => <Ts value={a.created} />,
    },
  ];

  return (
    <div className="fade-in">
      <PageHead
        page="apps"
        sub="OIDC relying parties, API resources, and (reserved) SAML service providers, registered per project."
        actions={
          canCreate && (
            <Link className="btn primary" href="/applications/new">
              <Icon name="plus" size={15} sw={2.2} />
              Register application
            </Link>
          )
        }
      />

      <DataTable
        id="applications"
        list={list}
        columns={columns}
        rowKey={(a) => a.id}
        onRowClick={(a) => router.push(`/applications/${a.id}`)}
        noun="application"
        empty="No applications match this filter."
        exportName="applications"
        search={{ fields: "the application name", placeholder: "Search applications…" }}
        filters={<StateFilter list={list} />}
      />
    </div>
  );
}
