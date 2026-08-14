"use client";

import { useCallback, useEffect, useState } from "react";
import { Icon } from "@/components/console/icons";
import { EntityHeader, FullPage, Modal, SectionCard, Tabs } from "@/components/console/overlays";
import { Btn, confirmAction, Field, MonoChip, Toggle, ViewNotice } from "@/components/console/primitives";
import { useConsole, usePending } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { rowActivation } from "@/components/console/data-table";
import { describeStatus, isIAMOwner, mutationMessage, scopesApi, UnauthorizedError, type Mapper, type MapperBody, type Scope } from "@/lib/console-api";

/** The noun `describeStatus` builds every scopes sentence from. */
const SCOPES_RESOURCE = "scopes and claim mappers";

const SOURCE_TYPES: { v: number; label: string; disabled?: boolean }[] = [
  { v: 1, label: "User attribute" },
  // Nothing writes `users.attributes`, so a bag mapper would silently resolve to
  // nothing — offered but not selectable, same as membership below.
  { v: 2, label: "Custom attribute (bag) (coming soon)", disabled: true },
  { v: 3, label: "Membership (coming soon)" },
  { v: 4, label: "Static value" },
];

const SCOPE_TABS = ["Settings", "Claim mappers"];

function sourceLabel(v: number): string {
  return SOURCE_TYPES.find((s) => s.v === v)?.label ?? "Unknown";
}

export function ScopesView() {
  const { me } = useConsole();
  // Scopes and claim mappers are IAM_OWNER-only server-side; mirror that here so a
  // non-owner isn't offered controls that can only fail. The gateway re-checks.
  const canWrite = isIAMOwner(me);
  const [scopes, setScopes] = useState<Scope[] | null>(null);
  const [error, setError] = useState<{ title: string; body: string } | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  // AZ-3: the read itself requires IAM_OWNER, and this view is in the nav for
  // every tenant member. A refusal names the role instead of rendering an empty
  // table that reads as "this tenant has no scopes".
  const load = useCallback(() => {
    scopesApi
      .list()
      .then((out) => {
        if (!out.ok) {
          setScopes([]);
          setError(describeStatus({ state: out.reason }, SCOPES_RESOURCE, "IAM_OWNER"));
          return;
        }
        setError(null);
        setScopes(out.data);
      })
      .catch((e: unknown) => {
        if (e instanceof UnauthorizedError) throw e;
        setScopes([]);
        setError(describeStatus({ state: "error", message: mutationMessage(e) }, SCOPES_RESOURCE));
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const open = scopes?.find((s) => s.id === openId) ?? null;

  if (creating) return <CreateScopePage onClose={() => setCreating(false)} onCreated={load} />;
  if (open) return <ScopeDetailPage scope={open} canWrite={canWrite} onClose={() => setOpenId(null)} onChanged={load} />;

  return (
    <div className="fade-in">
      <PageHead
        page="scopes"
        sub={
          <>
            The scopes this issuer advertises and the claims each releases. Builtin scopes are name-locked; their standard
            claim mappers stay editable.
          </>
        }
        actions={
          canWrite && (
            <>
              <button type="button" className="btn primary" onClick={() => setCreating(true)}>
                <Icon name="plus" size={15} sw={2.2} />
                New scope
              </button>
            </>
          )
        }
      />

      {error ? (
        <ViewNotice title={error.title} body={error.body} onRetry={load} />
      ) : (
      <div className="card" style={{ overflow: "auto hidden" }}>
        <table className="tbl" aria-label="Scopes">
          <thead>
            <tr>
              <th scope="col">Scope</th>
              <th scope="col" className="hide-md">Display name</th>
              <th scope="col">Claims</th>
              <th scope="col">Default</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {(scopes ?? []).map((s) => (
              <tr key={s.id} {...rowActivation(() => setOpenId(s.id))} className={"clickable" + (openId === s.id ? " selected" : "")}>
                <td>
                  <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className="mono" style={{ fontWeight: 600 }}>
                      {s.name}
                    </span>
                    {s.isBuiltin && <span className="badge">builtin</span>}
                  </span>
                </td>
                <td className="hide-md">{s.displayName || "—"}</td>
                <td className="mono">{s.mapperCount}</td>
                <td>{s.isDefault ? <span className="badge accent">default</span> : "—"}</td>
                <td>
                  <span className={"badge" + (s.isEnabled ? " accent" : "")}>{s.isEnabled ? "enabled" : "disabled"}</span>
                </td>
              </tr>
            ))}
            {scopes && scopes.length === 0 && (
              <tr>
                <td colSpan={5} style={{ color: "var(--muted)", textAlign: "center", padding: 24 }}>
                  No scopes yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      )}
    </div>
  );
}

function ScopeDetailPage({
  scope,
  canWrite,
  onClose,
  onChanged,
}: {
  scope: Scope;
  canWrite: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { A } = useConsole();
  const [tab, setTab] = useState("Settings");
  const [displayName, setDisplayName] = useState(scope.displayName);
  const [description, setDescription] = useState(scope.description);
  const [name, setName] = useState(scope.name);
  const [isEnabled, setEnabled] = useState(scope.isEnabled);
  const [isDefault, setDefault] = useState(scope.isDefault);
  const [saving, run] = usePending();

  const [mappers, setMappers] = useState<Mapper[] | null>(null);
  const [editing, setEditing] = useState<Mapper | null | "new">(null);

  const loadMappers = useCallback(() => {
    scopesApi
      .mappers(scope.id)
      .then(setMappers)
      .catch((e) => A.toast(mutationMessage(e), "alert", "error"));
  }, [A, scope.id]);

  useEffect(() => {
    loadMappers();
  }, [loadMappers]);

  async function saveScope() {
    await run(
      () =>
        scopesApi.update(scope.id, {
          name: scope.isBuiltin ? scope.name : name.trim(),
          displayName: displayName.trim(),
          description: description.trim(),
          isEnabled,
          isDefault,
        }),
      { ok: "Scope saved", after: onChanged }
    );
  }

  async function del() {
    const ok = await confirmAction({
      title: `Delete the scope “${scope.name}”?`,
      body: `This cannot be undone. Every client that requests “${scope.name}” stops receiving it, and the ${mappers?.length ?? scope.mapperCount} claim mapper(s) attached to it are deleted with it — so the claims they released disappear from issued tokens.`,
      confirmLabel: "Delete scope",
      destructive: true,
    });
    if (!ok) return;
    if (await run(() => scopesApi.remove(scope.id), { ok: "Scope deleted", after: onChanged })) onClose();
  }

  // BL-3: claim-mapper deletion gets the confirmation and the in-flight guard
  // that scope deletion on this same page already had.
  async function delMapper(m: Mapper) {
    const ok = await confirmAction({
      title: `Remove the claim “${m.claimName}”?`,
      body: `Tokens issued for “${scope.name}” stop carrying this claim immediately. Any relying party that reads it — for authorization decisions included — sees it disappear on the next token.`,
      confirmLabel: "Remove claim",
      destructive: true,
    });
    if (!ok) return;
    await run(() => scopesApi.removeMapper(m.id), {
      ok: "Claim removed",
      after: () => {
        loadMappers();
        onChanged();
      },
    });
  }

  return (
    <FullPage backLabel="Scopes" crumb={scope.name} onBack={onClose}>
      <EntityHeader
        tile={
          <span className="entity-tile">
            <Icon name="scroll" size={26} />
          </span>
        }
        title={<span style={{ fontFamily: "var(--font-mono)" }}>{scope.name}</span>}
        meta={
          <>
            <span className="badge">{scope.isBuiltin ? "builtin" : "custom"}</span>
            <span className={"badge" + (isEnabled ? " accent" : "")}>{isEnabled ? "enabled" : "disabled"}</span>
            {isDefault && <span className="badge accent">default</span>}
            <span>Scope ID</span>
            <MonoChip value={scope.id} toast={A.toast} />
          </>
        }
      />
      <Tabs tabs={SCOPE_TABS} value={tab} onChange={setTab} />

      {tab === "Settings" && (
        <div>
          <SectionCard title="Basic Information" desc="The scope string clients request, and how it is presented on the consent screen.">
            <div>
              <Field label="Scope string">
                <input
                  className="text-input"
                  style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}
                  value={name}
                  disabled={scope.isBuiltin || !canWrite}
                  onChange={(e) => setName(e.target.value)}
                />
              </Field>
              {scope.isBuiltin && (
                <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 4 }}>Builtin scope names are locked.</div>
              )}
            </div>
            <div>
              <Field label="Display name">
                <input className="text-input" value={displayName} disabled={!canWrite} onChange={(e) => setDisplayName(e.target.value)} />
              </Field>
            </div>
            <div>
              <Field label="Description">
                <input className="text-input" value={description} disabled={!canWrite} onChange={(e) => setDescription(e.target.value)} />
              </Field>
            </div>
            <div style={{ display: "flex", gap: 18, alignItems: "center" }}>
              <span style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
                <Toggle on={isEnabled} onChange={(v) => canWrite && setEnabled(v)} label="Enabled" /> Enabled
              </span>
              <span style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
                <Toggle on={isDefault} onChange={(v) => canWrite && setDefault(v)} label="Default for new clients" /> Default for new clients
              </span>
            </div>
            {canWrite && (
              <div className="form-actions">
                <Btn className="btn primary" pending={saving} onClick={saveScope}>
                  Save scope
                </Btn>
              </div>
            )}
          </SectionCard>

          {canWrite && !scope.isBuiltin && (
            <SectionCard danger title="Danger zone" desc="Deleting a scope is permanent. It must not be assigned to any client.">
              <div>
                <Btn className="btn danger-ghost" pending={saving} onClick={del}>
                  <Icon name="ban" size={15} /> Delete scope
                </Btn>
              </div>
            </SectionCard>
          )}
        </div>
      )}

      {tab === "Claim mappers" && (
        <SectionCard
          title="Claim mappers"
          tag={
            canWrite ? (
              <button type="button" className="btn sm ghost" onClick={() => setEditing("new")}>
                <Icon name="plus" size={13} /> Add claim
              </button>
            ) : undefined
          }
          desc="Each mapper releases one claim when this scope is granted, sourced from a user attribute, the custom bag, or a static value."
        >
          <div className="uri-list">
            {(mappers ?? []).map((m) => (
              <div className="uri-row" key={m.id} style={{ alignItems: "center" }}>
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span className="mono" style={{ fontWeight: 600 }}>
                    {m.claimName}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--muted)", marginLeft: 8 }}>{sourceLabel(m.sourceType)}</span>
                  <span style={{ fontSize: 11, color: "var(--muted)", marginLeft: 8 }}>{deliveryText(m)}</span>
                </span>
                {canWrite && (
                  <>
                    <button type="button" className="mono-chip" onClick={() => setEditing(m)}>
                      edit
                    </button>
                    <button type="button" className="icon-btn" aria-label="Remove" disabled={saving} onClick={() => void delMapper(m)}>
                      <Icon name="x" size={14} />
                    </button>
                  </>
                )}
              </div>
            ))}
            {mappers && mappers.length === 0 && (
              <div style={{ fontSize: 12, color: "var(--muted)", padding: "6px 0" }}>
                No claims — this scope releases nothing yet.
              </div>
            )}
          </div>
        </SectionCard>
      )}

      {editing !== null && (
        <MapperModal
          scopeId={scope.id}
          mapper={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            loadMappers();
            onChanged();
          }}
        />
      )}
    </FullPage>
  );
}

function deliveryText(m: Mapper): string {
  const t = [m.inUserInfo && "userinfo", m.inIdToken && "id_token", m.inAccessToken && "access_token"].filter(Boolean);
  return t.length ? t.join(" · ") : "no delivery";
}

function CreateScopePage({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [saving, run] = usePending();
  const valid = /^[A-Za-z0-9_:./-]{1,191}$/.test(name.trim());

  async function create() {
    if (!valid) return;
    const done = await run(
      () => scopesApi.create({ name: name.trim(), displayName: displayName.trim(), description: "", isEnabled: true, isDefault: false }),
      { ok: "Scope created", after: onCreated }
    );
    if (done) onClose();
  }

  return (
    <FullPage backLabel="Scopes" crumb="New scope" onBack={onClose}>
      <h1 className="entity-title" style={{ margin: "8px 0 4px" }}>
        New scope
      </h1>
      <div className="entity-meta" style={{ marginBottom: 22 }}>
        A scope is a named bundle of claims a client can request; add its claim mappers after it is created.
      </div>
      <SectionCard title="Basic Information" desc="Name the scope string clients request and the label shown on the consent screen.">
        <div>
          <Field label="Scope string">
            <input
              className="text-input"
              style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              placeholder="groups"
              value={name}
             
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 4 }}>
            Letters, digits and <span className="mono">_ : . / -</span>; no spaces.
          </div>
        </div>
        <div>
          <Field label="Display name">
            <input className="text-input" placeholder="Groups" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </Field>
        </div>
      </SectionCard>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" disabled={!valid} pending={saving} onClick={create}>
          Create scope
        </Btn>
      </div>
    </FullPage>
  );
}

function MapperModal({
  scopeId,
  mapper,
  onClose,
  onSaved,
}: {
  scopeId: string;
  mapper: Mapper | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [claimName, setClaimName] = useState(mapper?.claimName ?? "");
  const [sourceType, setSourceType] = useState(mapper?.sourceType ?? 1);
  const [sourceKey, setSourceKey] = useState(mapper?.sourceKey ?? "");
  const [sourceValue, setSourceValue] = useState(
    mapper?.sourceValue !== undefined ? JSON.stringify(mapper.sourceValue) : "",
  );
  const [inUserInfo, setUserInfo] = useState(mapper?.inUserInfo ?? true);
  const [inIdToken, setIdToken] = useState(mapper?.inIdToken ?? false);
  const [inAccessToken, setAccessToken] = useState(mapper?.inAccessToken ?? false);
  const [saving, run] = usePending();

  const isStatic = sourceType === 4;
  const valid = claimName.trim() !== "" && (isStatic ? sourceValue.trim() !== "" : sourceKey.trim() !== "");

  async function save() {
    if (!valid) return;
    const body: MapperBody = {
      claimName: claimName.trim(),
      sourceType,
      sourceKey: isStatic ? "" : sourceKey.trim(),
      inUserInfo,
      inIdToken,
      inAccessToken,
    };
    if (isStatic) {
      // Accept raw JSON (["a","b"], true, 42) or fall back to a plain string.
      try {
        body.sourceValue = JSON.parse(sourceValue);
      } catch {
        body.sourceValue = sourceValue;
      }
    }
    await run(() => (mapper ? scopesApi.updateMapper(mapper.id, body) : scopesApi.createMapper(scopeId, body)), {
      ok: "Claim saved",
      after: onSaved,
    });
  }

  return (
    <Modal title={mapper ? "Edit claim" : "Add claim"} onClose={onClose}>
      <div className="drawer-head">
        <span style={{ fontWeight: 600, fontSize: 15 }}>{mapper ? "Edit claim" : "Add claim"}</span>
        <button type="button" className="icon-btn" style={{ marginLeft: "auto" }} aria-label="Close" onClick={onClose}>
          <Icon name="x" size={17} />
        </button>
      </div>
      <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>
        <div>
          <Field label="Claim name">
            <input
              className="text-input"
              style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              placeholder="groups"
              value={claimName}
              onChange={(e) => setClaimName(e.target.value)}
            />
          </Field>
          <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 4 }}>
            Reserved protocol claims (sub, iss, exp…) and trust claims are rejected.
          </div>
        </div>
        <div>
          <Field label="Source">
            <select
              className="text-input"
              value={sourceType}
              onChange={(e) => setSourceType(Number(e.target.value))}
            >
              {SOURCE_TYPES.map((s) => (
                <option key={s.v} value={s.v} disabled={s.disabled}>
                  {s.label}
                </option>
              ))}
            </select>
          </Field>
        </div>
        {isStatic ? (
          <div>
            <Field label="Static value (JSON)">
              <input
                className="text-input"
                style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}
                placeholder='"value" or ["a","b"] or true'
                value={sourceValue}
                onChange={(e) => setSourceValue(e.target.value)}
              />
            </Field>
          </div>
        ) : (
          <div>
            <Field label="Source key">
              <input
                className="text-input"
                style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}
                placeholder={sourceType === 1 ? "email" : "attribute key"}
                value={sourceKey}
                onChange={(e) => setSourceKey(e.target.value)}
              />
            </Field>
          </div>
        )}
        <div>
          <span className="field-label" id="mapper-delivery-label">Delivery</span>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 6 }} role="group" aria-labelledby="mapper-delivery-label">
            <span style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
              <Toggle on={inUserInfo} onChange={setUserInfo} label="UserInfo response" /> UserInfo response
            </span>
            <span style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
              <Toggle on={inIdToken} onChange={setIdToken} label="ID token" /> ID token
            </span>
            <span style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
              <Toggle on={inAccessToken} onChange={setAccessToken} label="Access token" /> Access token
            </span>
            {inAccessToken && (
              <div style={{ fontSize: 11.5, color: "var(--warn)", display: "flex", gap: 6, alignItems: "flex-start" }}>
                <Icon name="alert" size={14} sw={2} style={{ flexShrink: 0, marginTop: 1 }} />
                Access tokens are bearer credentials that can&apos;t be revoked before they expire — avoid putting PII here.
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="drawer-foot">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" style={{ marginLeft: "auto" }} disabled={!valid} pending={saving} onClick={save}>
          Save claim
        </Btn>
      </div>
    </Modal>
  );
}
