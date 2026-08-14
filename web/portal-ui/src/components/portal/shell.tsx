"use client";

import { useRef, useState } from "react";

import { Icon, BrandMark } from "./icons";
import { Avatar, Drawer, Menu, ToastHost, type ToastItem } from "./primitives";
import { UserProvider, useUser } from "./flow-context";
import { spaces as ALL_SPACES, accessRequests, notifications as NOTIFS } from "@/lib/portal-data";
import type { Actions, PortalUser, Space } from "@/lib/types";

import { HomeView } from "./views/home";
import { ProfileView } from "./views/profile";
import { SecurityView } from "./views/security";
import { AppsView } from "./views/apps";
import { DevicesView } from "./views/devices";
import { ActivityView } from "./views/activity";
import { SupportView } from "./views/support";

// App root — mirrors the mockup's PortalApp (portal/app.jsx). The design's
// "tweaks" panel and sidebar/topbar toggle were mockup-only; this ships the
// topbar nav. The user comes from the server (OIDC /userinfo). Identity "spaces"
// are placeholder (no multi-tenant self-service API) — the switcher is local.

export function PortalApp({ user }: { user: PortalUser }) {
  return (
    <UserProvider user={user}>
      <PortalShell />
    </UserProvider>
  );
}

function PortalShell() {
  const [page, setPage] = useState("home");
  const [spaceId, setSpaceId] = useState("personal");
  const [notifOpen, setNotifOpen] = useState(false);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const toastId = useRef(0);
  const contentRef = useRef<HTMLDivElement>(null);

  const spaces = ALL_SPACES;

  function toast(msg: string, icon?: string) {
    const id = ++toastId.current;
    setToasts((ts) => ts.concat([{ id, msg, icon }]));
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), 3000);
  }

  const A: Actions = {
    toast,
    nav: (p: string) => { setPage(p); if (contentRef.current) contentRef.current.scrollTop = 0; },
  };

  function switchSpace(id: string) {
    setSpaceId(id);
    setPage("home");
    toast("Switched to " + (spaces.find((s) => s.id === id) || ({} as Space)).name, "globe");
  }

  const unread = NOTIFS.filter((n) => n.unread).length;
  const pendingReqs = accessRequests.filter((r) => r.status === "pending").length;

  return (
    <div className="shell shell-top">
      <div className="main">
        <TopNav page={page} onNav={A.nav} spaceId={spaceId} spaces={spaces}
          onSpace={switchSpace} unread={unread} pendingReqs={pendingReqs}
          onBell={() => setNotifOpen(true)} />
        <div className="content" ref={contentRef}>
          <div className="content-inner">
            {page === "home" && <HomeView spaceId={spaceId} spaces={spaces} A={A} heroStyle="spotlight" />}
            {page === "profile" && <ProfileView A={A} spaceId={spaceId} spaces={spaces} />}
            {page === "security" && <SecurityView A={A} />}
            {page === "apps" && <AppsView A={A} spaceId={spaceId} spaces={spaces} />}
            {page === "devices" && <DevicesView A={A} />}
            {page === "activity" && <ActivityView A={A} />}
            {page === "support" && <SupportView A={A} />}
          </div>
        </div>
      </div>

      {notifOpen && <NotificationsDrawer onClose={() => setNotifOpen(false)} A={A} />}
      <ToastHost toasts={toasts} />
    </div>
  );
}

/* ---------- Top navigation ---------- */
function TopNav({ page, onNav, spaceId, spaces, onSpace, unread, onBell, pendingReqs }: {
  page: string;
  onNav: (p: string) => void;
  spaceId: string;
  spaces: Space[];
  onSpace: (id: string) => void;
  unread: number;
  onBell: () => void;
  pendingReqs: number;
}) {
  const [switcherOpen, setSwitcherOpen] = useState(false);
  const [acctOpen, setAcctOpen] = useState(false);
  // Initialize from the pre-paint theme the layout script applied (guarded for
  // SSR). The theme-dependent label isn't rendered until the menu opens, so this
  // never causes a hydration mismatch.
  const [theme, setTheme] = useState<"light" | "dark">(() =>
    typeof document !== "undefined" && document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light"
  );
  const u = useUser();
  const space = spaces.find((s) => s.id === spaceId) || spaces[0];

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("ao-portal-theme", next); } catch { /* ignore */ }
  }

  const NAV: { id: string; label: string; icon: string; count?: number; dot?: boolean }[] = [
    { id: "home", label: "Home", icon: "home" },
    { id: "profile", label: "Profile", icon: "idcard" },
    { id: "security", label: "Security", icon: "shield" },
    { id: "apps", label: "Apps", icon: "apps", count: pendingReqs },
    { id: "devices", label: "Devices", icon: "laptop" },
    { id: "activity", label: "Activity", icon: "clock", dot: unread > 0 },
    { id: "support", label: "Support", icon: "help" },
  ];

  return (
    <header className="topnav">
      <div className="tn-inner">
        <div className="tn-brand">
          <BrandMark size={26} />
          <span className="brand-name">Alpha<span>Omega</span></span>
          <span className="console-tag">ID</span>
        </div>
        <nav className="tn-nav">
          {NAV.map((it) => (
            <button key={it.id} type="button" className={"tn-item" + (page === it.id ? " active" : "")} onClick={() => onNav(it.id)}>
              <Icon name={it.icon} size={16} sw={2} />
              <span className="tn-label">{it.label}</span>
              {it.count != null && it.count > 0 && <span className="count">{it.count}</span>}
              {it.dot && !it.count && <span className="dot-badge"></span>}
            </button>
          ))}
        </nav>
        <div className="tn-actions">
          <div style={{ position: "relative" }}>
            <button type="button" className="tn-space" onClick={() => setSwitcherOpen(!switcherOpen)}>
              <span className="org-tile" style={{ width: 28, height: 28, borderRadius: 8, background: space.accent, color: "#fff", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 11, flexShrink: 0 }}>{space.tile}</span>
              <span className="tn-space-nm">{space.name}</span>
              <Icon name="chevD" size={13} sw={2} style={{ color: "var(--muted)" }} />
            </button>
            {switcherOpen && (
              <Menu onClose={() => setSwitcherOpen(false)} align="right">
                <div className="menu-label">Your identity spaces · Not Wired</div>
                {spaces.map((s) => (
                  <button key={s.id} onClick={() => { onSpace(s.id); setSwitcherOpen(false); }}>
                    <span className="org-tile" style={{ width: 24, height: 24, borderRadius: 7, fontSize: 10, background: s.accent, color: "#fff", display: "grid", placeItems: "center", fontWeight: 700, flexShrink: 0 }}>{s.tile}</span>
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span style={{ display: "block", fontWeight: 600 }}>{s.name}</span>
                      <span style={{ display: "block", fontSize: 11, color: "var(--muted)" }}>{s.kind} · {s.type}</span>
                    </span>
                    {s.id === spaceId && <Icon name="check" size={14} sw={2.6} style={{ color: "var(--accent)" }} />}
                  </button>
                ))}
              </Menu>
            )}
          </div>
          <button type="button" className="icon-btn" aria-label="Notifications" onClick={onBell}>
            <Icon name="bell" size={18} />
            {unread > 0 && <span className="notif-dot"></span>}
          </button>
          <div style={{ position: "relative" }}>
            <button type="button" className="acct-btn" style={{ paddingRight: 8 }} onClick={() => setAcctOpen(!acctOpen)}>
              <Avatar name={u.displayName} size={32} hue={u.avatarHue} />
              <Icon name="chevD" size={13} sw={2} style={{ color: "var(--muted)" }} />
            </button>
            {acctOpen && (
              <Menu onClose={() => setAcctOpen(false)} align="right">
                <div style={{ padding: "8px 10px 6px", display: "flex", gap: 10, alignItems: "center" }}>
                  <Avatar name={u.displayName} size={36} hue={u.avatarHue} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{u.displayName}</div>
                    <div style={{ fontSize: 12, color: "var(--muted)", overflow: "hidden", textOverflow: "ellipsis" }}>{u.email}</div>
                  </div>
                </div>
                <div style={{ height: 1, background: "var(--border-soft)", margin: "4px 4px" }}></div>
                <button onClick={() => { onNav("profile"); setAcctOpen(false); }}><Icon name="idcard" size={16} sw={2} />My profile</button>
                <button onClick={() => { onNav("security"); setAcctOpen(false); }}><Icon name="shield" size={16} sw={2} />Security</button>
                <button onClick={toggleTheme}><Icon name={theme === "dark" ? "sparkle" : "shieldHalf"} size={16} sw={2} />{theme === "dark" ? "Light mode" : "Dark mode"}</button>
                <div style={{ height: 1, background: "var(--border-soft)", margin: "4px 4px" }}></div>
                <a href="/auth/logout" style={{ display: "flex", alignItems: "center", gap: 9, width: "100%", fontSize: 13, fontWeight: 500, color: "var(--error)", padding: "8px 10px", borderRadius: 7, textDecoration: "none" }}><Icon name="logout" size={16} sw={2} />Sign out</a>
              </Menu>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}

/* ---------- Notifications drawer (shared) ---------- */
function NotificationsDrawer({ onClose, A }: { onClose: () => void; A: Actions }) {
  const [items, setItems] = useState(NOTIFS);
  const unread = items.filter((n) => n.unread).length;
  function markAll() { setItems((v) => v.map((n) => ({ ...n, unread: false }))); A.toast("All caught up"); }
  function open(n: (typeof NOTIFS)[number]) {
    setItems((v) => v.map((x) => (x.id === n.id ? { ...x, unread: false } : x)));
    if (n.action && n.action !== "home") { A.nav(n.action); onClose(); }
  }
  const TONE: Record<string, string> = { warn: "warn", accent: "accent", good: "good", neutral: "neutral" };
  return (
    <Drawer onClose={onClose} width={400}>
      <div className="drawer-head">
        <Icon name="bell" size={18} sw={2} style={{ color: "var(--accent)" }} />
        <span className="card-title">Notifications</span>
        {unread > 0 && <span className="badge accent">{unread} new</span>}
        <span style={{ marginLeft: "auto" }}><button type="button" className="icon-btn" onClick={onClose}><Icon name="x" size={18} /></button></span>
      </div>
      <div className="drawer-body" style={{ padding: 10 }}>
        {items.map((n) => (
          <div key={n.id} className="notif-row" onClick={() => open(n)}>
            <span className={"nicon " + TONE[n.tone]}><Icon name={n.tone === "warn" ? "alert" : n.tone === "accent" ? "key" : n.tone === "good" ? "check" : "bell"} size={17} sw={2} /></span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="nttl">{n.title}</div>
              <div className="nsub">{n.detail}</div>
            </div>
            <span className="ntime">{n.time}</span>
            {n.unread && <span className="unread-dot"></span>}
          </div>
        ))}
      </div>
      <div className="drawer-foot">
        <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={markAll}>Mark all read</button>
        <button type="button" className="btn primary" style={{ flex: 1 }} onClick={() => { A.nav("activity"); onClose(); }}>View all activity</button>
      </div>
    </Drawer>
  );
}
