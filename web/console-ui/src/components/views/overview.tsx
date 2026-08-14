"use client";

import { Icon } from "@/components/console/icons";
import { Avatar, KV, Ts } from "@/components/console/primitives";
import { useConsole, useCounts, usePagedList } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { rowActivation } from "@/components/console/data-table";
import { pages } from "@/lib/console-api";
import { nameOr, orUnknown } from "@/lib/helpers";

export function OverviewView() {
  const { db, tenantId, A } = useConsole();
  const tenant = db.tenants.find((t) => t.id === tenantId)!;
  // Tiles read scoped totals, not the length of a held collection — one counted
  // request each, which is exactly what `total` on a first page is for.
  const counts = useCounts();
  // The recent-sessions card wants the newest handful, which is the head of the
  // sessions list. One small page, no *Load more*: this is a summary, and the
  // Sessions view is one click away for the rest.
  const recent = usePagedList(pages.sessions, "sessions", { limit: 10 });
  const keys = db.keys.filter((k) => k.tenantId === tenantId);
  const sigActive = keys.filter((k) => k.use === 1 && k.state === 1).length;
  const pc = db.providerConfigs[tenantId];

  const STATS = [
    { lbl: "Organizations", icon: "building", val: counts.orgs, nav: "orgs" },
    { lbl: "Projects", icon: "folder", val: counts.projects, nav: "projects" },
    { lbl: "Applications", icon: "apps", val: counts.apps, nav: "apps" },
    { lbl: "Users", icon: "users", val: counts.users, nav: "users" },
  ];

  return (
    <div className="fade-in">
      <PageHead
        page="overview"
        sub={
          <>
            {tenant.name} tenant · everything scoped to this tenant&apos;s organizations, projects and users.
          </>
        }
        actions={
          <>
            <button type="button" className="btn ghost" onClick={() => A.nav("sessions")}>
              <Icon name="fingerprint" size={15} />
              {counts.sessions} sessions
            </button>
          </>
        }
      />

      <div className="stat-grid">
        {STATS.map((s) => (
          <button type="button" key={s.lbl} className="card stat" onClick={() => A.nav(s.nav)}>
            <div className="lbl">
              <Icon name={s.icon} size={14} sw={2} />
              {s.lbl}
            </div>
            <div className="val">{s.val}</div>
            <div className="delta">
              <span className="vs">in {tenant.name}</span>
            </div>
          </button>
        ))}
      </div>

      {/* Full width, not a `.dash-row` pair: the sign-ins chart that shared this
          row was a fixture rendered inside a live view, and no endpoint aggregates
          the real series. Removed rather than relabelled — see design.md decision 9. */}
      <div className="card" style={{ marginBottom: 14 }}>
        <div className="card-head">
          <span className="card-title">OIDC provider</span>
          <span className="spacer" />
          <button type="button" className="btn sm ghost" onClick={() => A.nav("provider")}>
            Configure
          </button>
        </div>
        <div className="card-pad" style={{ paddingTop: 12 }}>
          <KV k="Issuer" v={<span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}>{pc ? pc.issuer : "—"}</span>} />
          <KV k="PKCE" v={pc && pc.requirePkce ? <span className="badge green">Required (S256)</span> : <span className="badge amber">Optional</span>} />
          <KV k="Access token" v={pc ? pc.accessTokenType : "—"} />
          <KV k="Refresh rotation" v={pc && pc.refreshRotation ? "On use" : "Reuse allowed"} />
          <KV
            k="Active signing keys"
            v={
              <button type="button" className="mono-chip" onClick={() => A.nav("keys")}>
                {sigActive} active
              </button>
            }
          />
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <span className="card-title">Recent login sessions</span>
          <span className="spacer" />
          <button type="button" className="btn sm ghost" onClick={() => A.nav("sessions")}>
            View all
            <Icon name="arrowR" size={13} />
          </button>
        </div>
        <div style={{ padding: "12px 0 4px" }}>
          <table className="tbl" aria-label="Recent sessions">
            <thead>
              <tr>
                <th scope="col">User</th>
                <th scope="col">Factors</th>
                <th scope="col" className="hide-md">Client links</th>
                <th scope="col" className="hide-md">IP</th>
                <th scope="col">Expires</th>
                <th scope="col">State</th>
              </tr>
            </thead>
            <tbody>
              {recent.items.map((s) => {
                const who = nameOr(s.userName, s.userId);
                return (
                  <tr key={s.id} {...rowActivation(() => A.nav("sessions"))}>
                    <td>
                      <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <Avatar name={who} size={26} />
                        <span style={{ fontWeight: 600 }}>{who}</span>
                      </span>
                    </td>
                    <td>
                      <span className="chip-row">
                        {s.factors.map((f) => (
                          <span key={f.amr} className="chip">
                            {f.amr}
                          </span>
                        ))}
                      </span>
                    </td>
                    <td className="hide-md mono">
                      {s.links.length} app{s.links.length === 1 ? "" : "s"}
                    </td>
                    <td className="hide-md mono">{orUnknown(s.ip)}</td>
                    <td className="mono">
                      <Ts value={s.expires} />
                    </td>
                    <td>
                      {s.state === 1 ? (
                        <span className="badge green">
                          <span className="bdot" />
                          Active
                        </span>
                      ) : (
                        <span className="badge gray">Terminated</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!recent.loading && recent.items.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: "center", color: "var(--muted)", padding: 24 }}>
                    No login sessions in scope.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
