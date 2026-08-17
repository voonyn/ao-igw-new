"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon, BrandMark } from "./icons";
import { Avatar } from "./primitives";
import { Menu } from "./overlays";
import { useConsole, useCounts } from "./store";
import { initials, PAGE_PATH, PAGE_TITLES } from "@/lib/helpers";

interface NavItem {
  id: string;
  icon: string;
  count?: number;
  /** Tenant-scoped view: shown only to tenant managers (IAM_*). */
  tenantOnly?: boolean;
}

export function Sidebar() {
  const { db, tenantId, me, accessibleOrgs, selectedOrgId, A } = useConsole();
  const counts = useCounts();
  const pathname = usePathname();
  const [switcherOpen, setSwitcherOpen] = useState(false);

  const tenant = db.tenants.find((t) => t.id === tenantId) || db.tenants[0];
  const primaryDomain = (tenant?.domains.find((d) => d.isPrimary) || tenant?.domains[0] || { domain: "—" }).domain;
  const selectedOrg = accessibleOrgs.find((o) => o.id === selectedOrgId) || null;
  const scopeName = selectedOrg ? selectedOrg.name : tenant?.name || "—";

  // No `label` here by design: a nav item is named by `PAGE_TITLES` (helpers.ts)
  // like the breadcrumb and the page heading are. A second table is how /tenants
  // came to carry one name in the nav and another everywhere else on the same
  // screen.
  const NAV: { section: string; items: NavItem[] }[] = [
    {
      // Not "Tenant": this sits directly under the scope control, where that
      // heading reads as a tenant selector over a menu that switches
      // organizations. These are the tenant's directory objects.
      section: "Directory",
      items: [
        { id: "overview", icon: "grid" },
        { id: "orgs", icon: "building", count: counts.orgs },
        { id: "projects", icon: "folder", count: counts.projects },
        { id: "apps", icon: "apps", count: counts.apps },
        { id: "users", icon: "users", count: counts.users },
        { id: "members", icon: "idcard" },
      ],
    },
    {
      section: "OIDC Provider",
      items: [
        { id: "provider", icon: "sliders", tenantOnly: true },
        { id: "scopes", icon: "layers", tenantOnly: true },
        { id: "keys", icon: "key", count: counts.keys, tenantOnly: true },
        { id: "sessions", icon: "fingerprint", count: counts.sessions },
      ],
    },
    {
      section: "Tenant",
      items: [
        { id: "tenants", icon: "server", tenantOnly: true },
        { id: "policies", icon: "scroll", tenantOnly: true },
        { id: "notifications", icon: "mail", tenantOnly: true },
        { id: "audit", icon: "laptop", tenantOnly: true },
        { id: "bootstrap", icon: "rocket", tenantOnly: true },
      ],
    },
    {
      section: "Preview · not wired",
      items: [
        { id: "groups", icon: "group" },
        { id: "roles", icon: "shield" },
        { id: "catalog", icon: "layers" },
      ],
    },
  ];

  const userName = me.displayName || me.username || "—";
  const userRole = me.tenantRoles[0] || me.orgMemberships[0]?.roles[0] || "Member";

  return (
    <aside className="sidebar">
      <Link href={PAGE_PATH.overview} className="sb-brand">
        <BrandMark size={28} />
        <span className="brand-name">
          Alpha<span>Omega</span>
        </span>
        <span className="console-tag">Admin</span>
      </Link>

      {/* The tenant this console is bound to — stated, not selectable. The
          control below switches ORGANIZATION within it.

          Deliberately not a tenant switcher (design.md decision 2): the gateway
          derives tenant from the access token's `iss`, the BFF pins one issuer,
          the sealed cookie carries no tenant, and no endpoint lists the tenants
          a caller can reach. Switching tenants means authenticating against
          another issuer — a different URL, not a menu. */}
      <div className="sb-section">{tenant?.name || "Tenant"}</div>

      <div style={{ position: "relative" }}>
        <button
          type="button"
          className="sb-org"
          aria-haspopup="menu"
          aria-expanded={switcherOpen}
          onClick={() => setSwitcherOpen((v) => !v)}
        >
          <span className="org-tile">{initials(scopeName)}</span>
          <span className="org-info" style={{ minWidth: 0 }}>
            <span className="org-name" style={{ display: "block" }}>
              {selectedOrg ? selectedOrg.name : "All organizations"}
            </span>
            <span className="org-plan">{selectedOrg ? "Organization" : primaryDomain}</span>
          </span>
          <span className="org-chev" style={{ marginLeft: "auto", display: "inline-flex" }}>
            <Icon name="chevUD" size={14} sw={2} style={{ color: "#84878D" }} />
          </span>
        </button>
        {switcherOpen && (
          <Menu onClose={() => setSwitcherOpen(false)} align="left">
            <div className="menu-label">Switch organization</div>
            <OrgRow
              name={"All organizations"}
              active={selectedOrgId === null}
              onClick={() => {
                A.selectOrg(null);
                setSwitcherOpen(false);
              }}
            />
            {accessibleOrgs.map((o) => (
              <OrgRow
                key={o.id}
                name={o.name}
                active={o.id === selectedOrgId}
                onClick={() => {
                  A.selectOrg(o.id);
                  setSwitcherOpen(false);
                }}
              />
            ))}
          </Menu>
        )}
      </div>

      {/* One named navigation landmark over every section, rather than four
          anonymous ones — a screen reader's landmark list needs to say which
          navigation this is. */}
      <nav aria-label="Console">
        {NAV.map((sec) => {
          const items = sec.items.filter((it) => !it.tenantOnly || me.isTenantManager);
          if (items.length === 0) return null;
          return (
            <div key={sec.section}>
              <div className="sb-section">{sec.section}</div>
              <div className="sb-nav">
                {items.map((it) => {
                  const path = PAGE_PATH[it.id];
                  const active = pathname === path;
                  return (
                    <Link key={it.id} href={path} className={"sb-item" + (active ? " active" : "")} aria-current={active ? "page" : undefined}>
                      <Icon name={it.icon} size={17} />
                      {/* Stays in the accessibility tree when the rail collapses
                          below 920px — the CSS hides it visually rather than
                          with `display: none`, so no parallel `aria-label` can
                          drift away from what is on screen. */}
                      <span className="sb-label">{PAGE_TITLES[it.id]}</span>
                      {it.count != null && <span className="count">{it.count}</span>}
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      <div className="sb-foot">
        <div className="sb-user">
          <Avatar name={userName} size={32} />
          <span className="sb-utext" style={{ minWidth: 0, flex: 1 }}>
            <span className="nm" style={{ display: "block" }}>
              {userName}
            </span>
            <span className="rl">{userRole}</span>
          </span>
          <Link href="/auth/logout" className="sb-uicon" style={{ display: "inline-flex" }} aria-label="Sign out">
            <Icon name="logout" size={16} style={{ color: "#84878D" }} />
          </Link>
        </div>
      </div>
    </aside>
  );
}

function OrgRow({ name, active, onClick }: { name: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick}>
      <span
        className="org-tile"
        style={{
          width: 22,
          height: 22,
          borderRadius: 6,
          fontSize: 10,
          background: active ? "var(--accent)" : "var(--muted-2)",
          color: "#fff",
          display: "grid",
          placeItems: "center",
          fontWeight: 700,
        }}
      >
        {initials(name)}
      </span>
      <span style={{ flex: 1 }}>{name}</span>
      {active && <Icon name="check" size={14} sw={2.6} style={{ color: "var(--accent)" }} />}
    </button>
  );
}
