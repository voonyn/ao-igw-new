"use client";

import { useState } from "react";
import { Icon } from "@/components/console/icons";
import { Btn, confirmAction, EntityStateBadge, KV, MonoChip, Ts, VerifiedBadge } from "@/components/console/primitives";
import { EntityHeader, FullPage, ReadField, SectionCard, Tabs } from "@/components/console/overlays";
import { useConsole, useCounts, usePending, type Actions } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { rowActivation } from "@/components/console/data-table";
import { domainsApi, isIAMOwner } from "@/lib/console-api";
import { initials, orgName } from "@/lib/helpers";
import type { Db, Tenant } from "@/lib/types";

const TENANT_TABS = ["Settings", "Domains"];

// Tenant lifecycle itself (create/deactivate) is a CLI/IaC operation and isn't
// surfaced here at all. Domains are, because there is no other path to them:
// bootstrap writes them once and nothing else does.
const DOMAIN_ROLE = "Adding or removing a domain requires IAM_OWNER on this tenant.";

// What the write does NOT do. A row is inert until DNS, TLS and the reverse proxy
// also point this host at the gateway, and "verified" here is asserted, not proven
// — there is no DNS or HTTP challenge.
const DOMAIN_CAVEAT =
  "Adding a domain only maps it to this tenant. The host still has to resolve to this gateway in DNS, " +
  "serve a valid certificate, and be forwarded by the reverse proxy before anything answers on it. " +
  "Domains are marked verified on creation — no DNS or HTTP challenge is performed. " +
  "A new domain must share the registrable domain (eTLD+1) of the existing ones, or already-enrolled " +
  "passkeys will not work on it.";

function TenantDetailPage({
  db,
  tenant,
  A,
  onClose,
  currentTenantId,
}: {
  db: Db;
  tenant: Tenant;
  A: Actions;
  onClose: () => void;
  currentTenantId: string;
}) {
  const { accessibleOrgs, me } = useConsole();
  const counts = useCounts();
  const [tab, setTab] = useState("Settings");
  const [newDomain, setNewDomain] = useState("");
  const [busy, run] = usePending();
  // The endpoint is instance-scoped — it always writes the CALLER's tenant. So the
  // controls only appear on the caller's own tenant, never on a listed sibling
  // whose domains this page can read but not address.
  const canWriteDomains = isIAMOwner(me) && tenant.id === currentTenantId;

  async function addDomain() {
    const domain = newDomain.trim();
    if (!domain) return;
    if (await run(() => domainsApi.add(domain), { ok: "Added " + domain })) setNewDomain("");
  }

  async function removeDomain(domain: string) {
    const ok = await confirmAction({
      title: `Remove “${domain}”?`,
      body: `Requests arriving on this host stop resolving to this tenant — sign-in and every OIDC endpoint there begin returning errors. The mapping is deactivated rather than deleted, so it can be restored, and no other tenant can claim the host in the meantime.`,
      confirmLabel: "Remove domain",
      destructive: true,
    });
    if (!ok) return;
    await run(() => domainsApi.remove(domain), { ok: "Removed " + domain, icon: "ban" });
  }
  const defaultOrgName = tenant.defaultOrgId ? orgName(accessibleOrgs, tenant.defaultOrgId) : "";
  const issuer = db.providerConfigs[tenant.id]?.issuer;

  return (
    <FullPage backLabel="Tenants" crumb={tenant.name} onBack={onClose}>
      <EntityHeader
        tile={
          <span className="entity-tile" style={{ background: "var(--accent)", border: "none", color: "#fff", fontWeight: 700, fontSize: 19 }}>
            {initials(tenant.name)}
          </span>
        }
        title={tenant.name}
        meta={
          <>
            <EntityStateBadge state={tenant.state} />
            {tenant.id === currentTenantId && <span className="badge accent">current</span>}
            <span>
              {tenant.kind} · created <Ts value={tenant.created} />
            </span>
            <span>Tenant ID</span>
            <MonoChip value={tenant.id} toast={A.toast} />
          </>
        }
      />
      <Tabs tabs={TENANT_TABS} value={tab} onChange={setTab} />

      {tab === "Settings" && (
        <div>
          <SectionCard title="Basic Information" desc="Instance-level record. A tenant is an isolated IAM realm with its own OIDC provider.">
            <ReadField label="Name" value={tenant.name} />
            <ReadField label="Tenant ID" value={tenant.id} mono toast={A.toast} />
            {issuer && <ReadField label="Provider issuer" value={issuer} mono toast={A.toast} />}
            <KV k="Organizations" v={counts.orgs} />
          </SectionCard>

          <SectionCard title="Self-registration" desc="Users self-registering on this tenant land in its default organization.">
            <KV k="Default organization" v={defaultOrgName || <span style={{ color: "var(--muted)" }}>None — self-reg disabled</span>} />
          </SectionCard>
        </div>
      )}

      {tab === "Domains" && (
        <SectionCard title="Domains" desc="Bare hosts, globally unique — a domain resolves to exactly one tenant before any credential is seen.">
          <div className="uri-list">
            {tenant.domains.map((d) => (
              <div className="uri-row" key={d.domain}>
                <span className="uri" style={d.state === 2 ? { opacity: 0.5 } : undefined}>
                  {d.domain}
                </span>
                {d.isPrimary && <span className="badge accent">Primary</span>}
                {d.state === 2 && <span className="badge">Removed</span>}
                <VerifiedBadge on={d.isVerified} />
                {/* The primary is never removable: the issuer and the console's own
                    links derive from it, and nothing here can move it. */}
                {canWriteDomains && !d.isPrimary && d.state !== 2 && (
                  <Btn className="btn sm danger-ghost" pending={busy} onClick={() => removeDomain(d.domain)} aria-label={`Remove ${d.domain}`}>
                    <Icon name="ban" size={14} />
                    Remove
                  </Btn>
                )}
              </div>
            ))}
            {tenant.domains.length === 0 && <div style={{ fontSize: 13, color: "var(--muted)" }}>No domains mapped to this tenant.</div>}
          </div>
          {canWriteDomains && (
            <form
              style={{ display: "flex", gap: 8 }}
              onSubmit={(e) => {
                e.preventDefault();
                void addDomain();
              }}
            >
              <input
                className="text-input"
                style={{ height: 36, fontFamily: "var(--font-mono)", fontSize: 12 }}
                placeholder="auth.example.com"
                aria-label="New domain"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                disabled={busy}
              />
              <Btn type="submit" className="btn sm ghost" pending={busy} disabled={!newDomain.trim()}>
                <Icon name="plus" size={14} />
                Add
              </Btn>
            </form>
          )}
          <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 8 }}>{canWriteDomains ? DOMAIN_CAVEAT : DOMAIN_ROLE}</div>
        </SectionCard>
      )}
    </FullPage>
  );
}

export function TenantsView() {
  const { db, tenantId, A } = useConsole();
  const [openId, setOpenId] = useState<string | null>(null);
  const tenants = db.tenants.filter((t) => t.state !== 3);
  const open = tenants.find((t) => t.id === openId);

  if (open) return <TenantDetailPage db={db} tenant={open} A={A} currentTenantId={tenantId} onClose={() => setOpenId(null)} />;

  return (
    <div className="fade-in">
      <PageHead
        page="tenants"
        sub="Instance-level view. Each tenant is an isolated IAM realm with its own domains, organizations and OIDC provider."
      />

      <div className="card" style={{ overflow: "auto hidden" }}>
        <table className="tbl" aria-label="Tenants">
          <thead>
            <tr>
              <th scope="col">Tenant</th>
              <th scope="col">Primary domain</th>
              <th scope="col" className="hide-md">Domains</th>
              <th scope="col">State</th>
              <th scope="col" className="hide-md">Created</th>
            </tr>
          </thead>
          <tbody>
            {tenants.map((t) => {
              // Per-row org/user counts are gone here for the same reason as on
              // the organizations and projects lists: counting another
              // collection per row is a request per row. The tenant's own
              // detail panel carries the counts.
              const primary = t.domains.find((d) => d.isPrimary);
              return (
                <tr key={t.id} {...rowActivation(() => setOpenId(t.id))} className={"clickable" + (openId === t.id ? " selected" : "")}>
                  <td>
                    <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span
                        className="org-tile"
                        style={{
                          width: 28,
                          height: 28,
                          borderRadius: 8,
                          background: t.id === tenantId ? "var(--accent)" : "var(--accent-soft)",
                          color: t.id === tenantId ? "#fff" : "var(--accent-deep)",
                          display: "grid",
                          placeItems: "center",
                          fontWeight: 700,
                          fontSize: 11,
                        }}
                      >
                        {initials(t.name)}
                      </span>
                      <span style={{ fontWeight: 600 }}>
                        {t.name}
                        {t.id === tenantId && (
                          <span className="badge accent" style={{ marginLeft: 8 }}>
                            current
                          </span>
                        )}
                      </span>
                    </span>
                  </td>
                  <td className="mono">{primary ? primary.domain : "—"}</td>
                  <td className="hide-md mono">{t.domains.length}</td>
                  <td>
                    <EntityStateBadge state={t.state} />
                  </td>
                  <td className="hide-md mono">
                    <Ts value={t.created} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
