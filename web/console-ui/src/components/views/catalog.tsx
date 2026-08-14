"use client";

import { useState } from "react";
import { Icon } from "@/components/console/icons";
import { ProtoBanner, Toggle, UnbackedBtn } from "@/components/console/primitives";
import { Drawer } from "@/components/console/overlays";
import { useConsole } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { PROTO_NOTES } from "@/lib/helpers";
import type { LegacyApp } from "@/lib/types";

const sectionTitle: React.CSSProperties = { fontSize: 11.5, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--muted)", marginBottom: 10 };

function AppDrawer({
  app,
  onUpdateApp,
  onClose,
  toast,
}: {
  app: LegacyApp;
  onUpdateApp: (id: string, patch: Partial<LegacyApp>) => void;
  onClose: () => void;
  toast: (msg: string, icon?: string) => void;
}) {
  return (
    <Drawer title={app.name} onClose={onClose}>
      <div className="drawer-head">
        <span style={{ width: 40, height: 40, borderRadius: 11, background: app.tile, color: "#fff", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 17, flexShrink: 0 }}>{app.name[0]}</span>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 15, display: "flex", alignItems: "center", gap: 9 }}>
            {app.name}
            {app.status === "Healthy" ? (
              <span className="badge green">
                <span className="bdot" />
                Healthy
              </span>
            ) : (
              <span className="badge amber">
                <Icon name="alert" size={11} sw={2.4} />
                Sync issue
              </span>
            )}
          </div>
          <div style={{ fontSize: 12.5, color: "var(--muted)", marginTop: 1 }}>
            {app.users.toLocaleString()} assigned · owned by {app.owner}
          </div>
        </div>
        <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose} aria-label="Close">
          <Icon name="x" size={17} />
        </button>
      </div>

      <div className="drawer-body">
        <div style={sectionTitle}>Single sign-on</div>
        <div className="card" style={{ boxShadow: "none", marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", fontSize: 13 }}>
            <Icon name="lock" size={15} style={{ color: "var(--muted-2)" }} />
            <span style={{ color: "var(--muted)" }}>Protocol</span>
            <span style={{ marginLeft: "auto", fontWeight: 500 }}>{app.signOn}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderTop: "1px solid var(--border-soft)", fontSize: 13 }}>
            <Icon name="globe" size={15} style={{ color: "var(--muted-2)" }} />
            <span style={{ color: "var(--muted)" }}>Sign-in URL</span>
            <button className="btn sm ghost" style={{ marginLeft: "auto", height: 26, fontSize: 12 }} onClick={() => toast("Sign-in URL copied", "copy")}>
              <Icon name="copy" size={12} />
              Copy
            </button>
          </div>
        </div>

        <div style={sectionTitle}>Provisioning</div>
        <div className="card" style={{ boxShadow: "none", marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "11px 14px", fontSize: 13 }}>
            <Icon name="refresh" size={15} style={{ color: "var(--muted-2)" }} />
            <span style={{ fontWeight: 500 }}>SCIM provisioning</span>
            <span style={{ marginLeft: "auto" }}>
              <Toggle
                on={app.provisioning}
                label="SCIM provisioning"
                onChange={(v) => {
                  onUpdateApp(app.id, { provisioning: v });
                  toast(v ? "Provisioning enabled for " + app.name : "Provisioning paused for " + app.name, v ? "check" : "alert");
                }}
              />
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderTop: "1px solid var(--border-soft)", fontSize: 13 }}>
            <Icon name="clock" size={15} style={{ color: "var(--muted-2)" }} />
            <span style={{ color: "var(--muted)" }}>Last sync</span>
            <span style={{ marginLeft: "auto", fontWeight: 500 }}>{app.lastSync}</span>
          </div>
          {app.status !== "Healthy" && (
            <div style={{ display: "flex", alignItems: "center", gap: 9, margin: 12, padding: "10px 12px", borderRadius: 9, background: "var(--warn-soft)", fontSize: 12.5, color: "var(--warn)", fontWeight: 500 }}>
              <Icon name="alert" size={15} sw={2} />
              <span style={{ textWrap: "pretty" }}>Last 3 sync attempts failed — API token may be expired.</span>
              <button
                className="btn sm ghost"
                style={{ marginLeft: "auto", height: 26, fontSize: 12, flexShrink: 0 }}
                onClick={() => {
                  onUpdateApp(app.id, { status: "Healthy", lastSync: "just now" });
                  toast("Sync retried — connection restored");
                }}
              >
                Retry
              </button>
            </div>
          )}
        </div>

        <div style={sectionTitle}>Assigned groups</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {app.groups.map((g) => (
            <span className="chip" key={g}>
              <Icon name="group" size={12} />
              {g}
            </span>
          ))}
          <button className="chip" style={{ cursor: "pointer", borderStyle: "dashed", background: "transparent" }} onClick={() => toast("Group assignment coming to this prototype on request", "group")}>
            <Icon name="plus" size={11} sw={2.6} />
            Assign group
          </button>
        </div>
      </div>

      <div className="drawer-foot">
        {/* Was a toast claiming a download that never happened. SAML is reserved
            in the schema and unimplemented, so there is no metadata document to
            produce — disabled with the reason instead. */}
        <UnbackedBtn
          reason="SAML is reserved but unimplemented, so there is no metadata document to download."
          className="btn ghost"
          wrapStyle={{ flex: 1 }}
        >
          <Icon name="download" size={15} />
          SAML metadata
        </UnbackedBtn>
        <button className="btn danger-ghost" style={{ flex: 1 }} onClick={() => toast("Deactivation requires removing all assignments", "alert")}>
          <Icon name="ban" size={15} />
          Deactivate
        </button>
      </div>
    </Drawer>
  );
}

export function CatalogView() {
  const { legacy, legacyActions, A } = useConsole();
  const apps = legacy.apps;
  const [openId, setOpenId] = useState<string | null>(null);
  const openApp = apps.find((a) => a.id === openId);

  return (
    <div className="fade-in">
      <ProtoBanner>{PROTO_NOTES.catalog}</ProtoBanner>
      <PageHead
        page="catalog"
        sub={
          <>
            {apps.length} SSO-connected applications. Users sign in to each through AlphaOmega.
          </>
        }
        actions={
          <>
            <button className="btn primary" onClick={() => A.toast("App catalog coming to this prototype on request", "apps")}>
              <Icon name="plus" size={15} sw={2.4} />
              Connect app
            </button>
          </>
        }
      />
      <div className="apps-grid">
        {apps.map((a) => (
          <button
            type="button"
            className="card app-tile"
            key={a.id}
            style={{ padding: 18, display: "flex", alignItems: "center", gap: 13, cursor: "pointer" }}
            onClick={() => setOpenId(a.id)}
          >
            <span style={{ width: 40, height: 40, borderRadius: 11, background: a.tile, color: "#fff", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 16, flexShrink: 0 }}>{a.name[0]}</span>
            <span style={{ minWidth: 0, flex: 1 }}>
              <span style={{ display: "block", fontWeight: 600, fontSize: 14 }}>{a.name}</span>
              <span style={{ display: "block", fontSize: 12, color: "var(--muted)", marginTop: 1 }}>
                {a.users.toLocaleString()} assigned · {a.signOn}
              </span>
            </span>
            {a.status === "Healthy" ? (
              <span className="badge green">
                <span className="bdot" />
                Healthy
              </span>
            ) : (
              <span className="badge amber">
                <Icon name="alert" size={11} sw={2.4} />
                Sync issue
              </span>
            )}
          </button>
        ))}
      </div>
      {openApp && <AppDrawer app={openApp} onUpdateApp={legacyActions.updateApp} onClose={() => setOpenId(null)} toast={A.toast} />}
    </div>
  );
}
