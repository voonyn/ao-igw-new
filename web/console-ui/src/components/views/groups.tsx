"use client";

import { useState } from "react";
import { Icon } from "@/components/console/icons";
import { Avatar, ProtoBanner, SearchBox, Seg, SourceBadge, UnbackedBtn } from "@/components/console/primitives";
import { Drawer, Menu } from "@/components/console/overlays";
import { useConsole } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { rowActivation } from "@/components/console/data-table";
import { PROTO_NOTES } from "@/lib/helpers";
import type { LegacyGroup, LegacyRole, LegacyUser } from "@/lib/types";

const sectionTitle: React.CSSProperties = { fontSize: 11.5, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--muted)", marginBottom: 10 };

function GroupDrawer({
  group,
  users,
  roles,
  onUpdateGroup,
  onClose,
  toast,
}: {
  group: LegacyGroup;
  users: LegacyUser[];
  roles: LegacyRole[];
  onUpdateGroup: (id: string, patch: Partial<LegacyGroup>) => void;
  onClose: () => void;
  toast: (msg: string, icon?: string) => void;
}) {
  const [addingRole, setAddingRole] = useState(false);
  const roleName = (id: string) => roles.find((r) => r.id === id)?.name || id;
  const available = roles.filter((r) => !group.roles.includes(r.id));
  const memberPreview = users.slice(0, Math.min(6, group.members));

  return (
    <Drawer title={group.name} onClose={onClose}>
      <div className="drawer-head">
        <span style={{ width: 40, height: 40, borderRadius: 11, background: "var(--accent-soft)", color: "var(--accent)", display: "grid", placeItems: "center", flexShrink: 0 }}>
          <Icon name="group" size={19} />
        </span>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 15, display: "flex", alignItems: "center", gap: 9 }}>
            {group.name} <SourceBadge source={group.source} />
          </div>
          <div style={{ fontSize: 12.5, color: "var(--muted)", marginTop: 1 }}>
            {group.members.toLocaleString()} members · owned by {group.owner}
          </div>
        </div>
        <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose} aria-label="Close">
          <Icon name="x" size={17} />
        </button>
      </div>

      <div className="drawer-body">
        <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 20, textWrap: "pretty" }}>{group.desc}</p>

        <div style={{ ...sectionTitle, display: "flex", alignItems: "center" }}>
          Mapped roles
          <span style={{ marginLeft: "auto", position: "relative" }}>
            <button className="btn sm ghost" style={{ height: 26, fontSize: 12, textTransform: "none", letterSpacing: 0 }} onClick={() => setAddingRole((v) => !v)}>
              <Icon name="plus" size={12} sw={2.6} />
              Map role
            </button>
            {addingRole && (
              <Menu onClose={() => setAddingRole(false)} align="right">
                {available.map((r) => (
                  <button
                    key={r.id}
                    onClick={() => {
                      onUpdateGroup(group.id, { roles: group.roles.concat([r.id]) });
                      setAddingRole(false);
                      toast("Mapped " + r.name + " to " + group.name);
                    }}
                  >
                    <Icon name="key" size={14} />
                    {r.name}
                  </button>
                ))}
              </Menu>
            )}
          </span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 22 }}>
          {group.roles.map((rid) => (
            <div key={rid} style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", border: "1px solid var(--border)", borderRadius: 10, background: "var(--field)" }}>
              <span style={{ width: 28, height: 28, borderRadius: 8, background: "var(--accent-soft)", color: "var(--accent)", display: "grid", placeItems: "center", flexShrink: 0 }}>
                <Icon name="key" size={14} />
              </span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{roleName(rid)}</div>
                <div style={{ fontSize: 11.5, color: "var(--muted)" }}>Granted to every member</div>
              </div>
              <button
                className="icon-btn"
                style={{ marginLeft: "auto", width: 28, height: 28 }}
                aria-label={"Unmap " + roleName(rid)}
                onClick={() => {
                  if (group.roles.length === 1) {
                    toast("A group must keep at least one mapped role", "alert");
                    return;
                  }
                  onUpdateGroup(group.id, { roles: group.roles.filter((r) => r !== rid) });
                  toast("Unmapped " + roleName(rid) + " from " + group.name);
                }}
              >
                <Icon name="x" size={14} />
              </button>
            </div>
          ))}
        </div>

        <div style={sectionTitle}>Applications granted</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 22 }}>
          {group.apps.map((a) => (
            <span className="chip" key={a}>
              <Icon name="apps" size={12} />
              {a}
            </span>
          ))}
        </div>

        <div style={sectionTitle}>Members</div>
        <div className="card" style={{ boxShadow: "none", marginBottom: 22 }}>
          {memberPreview.map((m, i) => (
            <div key={m.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 14px", borderTop: i ? "1px solid var(--border-soft)" : "none", fontSize: 13 }}>
              <Avatar name={m.name} size={26} />
              <span style={{ fontWeight: 500 }}>{m.name}</span>
              <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--muted)" }}>{m.dept}</span>
            </div>
          ))}
          {group.members > memberPreview.length && (
            <div style={{ padding: "9px 14px", borderTop: "1px solid var(--border-soft)", fontSize: 12.5, color: "var(--muted)" }}>
              + {(group.members - memberPreview.length).toLocaleString()} more members
            </div>
          )}
        </div>

        <div style={sectionTitle}>Provisioning</div>
        <div className="card" style={{ boxShadow: "none" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", fontSize: 13 }}>
            <Icon name="refresh" size={15} style={{ color: "var(--muted-2)" }} />
            <span style={{ color: "var(--muted)" }}>Source</span>
            <span style={{ marginLeft: "auto", fontWeight: 500 }}>{group.source === "SCIM" ? "SCIM — Workday" : "Manual membership"}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderTop: "1px solid var(--border-soft)", fontSize: 13 }}>
            <Icon name="clock" size={15} style={{ color: "var(--muted-2)" }} />
            <span style={{ color: "var(--muted)" }}>{group.expires ? "Expires" : "Last sync"}</span>
            <span style={{ marginLeft: "auto", fontWeight: 500 }}>{group.expires || group.synced}</span>
          </div>
        </div>
      </div>

      <div className="drawer-foot">
        {/* Was a toast claiming a queued export that no endpoint produced. Groups
            have no schema behind them at all yet, so there is nothing to walk —
            it stays disabled with the reason, like every other unbacked control. */}
        <UnbackedBtn
          reason="Groups aren't schema-backed yet, so there are no members to export."
          className="btn ghost"
          wrapStyle={{ flex: 1 }}
        >
          <Icon name="download" size={15} />
          Export members
        </UnbackedBtn>
        <button
          className="btn danger-ghost"
          style={{ flex: 1 }}
          onClick={() => toast(group.source === "SCIM" ? "SCIM groups are deleted at the source" : "Group archived", group.source === "SCIM" ? "alert" : "check")}
        >
          <Icon name="ban" size={15} />
          Archive group
        </button>
      </div>
    </Drawer>
  );
}

export function GroupsView() {
  const { legacy, legacyActions, A } = useConsole();
  const [q, setQ] = useState("");
  const [src, setSrc] = useState("All");
  const [openId, setOpenId] = useState<string | null>(null);
  const filtered = legacy.groups.filter((g) => g.name.toLowerCase().includes(q.toLowerCase()) && (src === "All" || g.source === src));
  const openGroup = legacy.groups.find((g) => g.id === openId);
  const roleName = (id: string) => legacy.roles.find((r) => r.id === id)?.name || id;

  return (
    <div className="fade-in">
      <ProtoBanner>{PROTO_NOTES.groups}</ProtoBanner>
      <PageHead
        page="groups"
        sub="Groups gather users for role mapping and app assignment. SCIM groups sync from Workday."
        actions={
          <>
            <button className="btn primary" onClick={() => A.toast("Group builder coming to this prototype on request", "group")}>
              <Icon name="plus" size={15} sw={2.4} />
              New group
            </button>
          </>
        }
      />

      <div className="filter-row" style={{ marginBottom: 14 }}>
        <SearchBox value={q} onChange={setQ} placeholder="Search groups…" />
        <Seg options={["All", "SCIM", "Manual"]} value={src} onChange={setSrc} />
      </div>

      <div className="card">
        <table className="tbl" aria-label="Groups">
          <thead>
            <tr>
              <th scope="col">Group</th>
              <th scope="col">Members</th>
              <th scope="col">Source</th>
              <th scope="col" className="hide-md">Mapped roles</th>
              <th scope="col" className="hide-md">Apps</th>
              <th scope="col" style={{ width: 36 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((g) => (
              <tr key={g.id} {...rowActivation(() => setOpenId(g.id))} className={"clickable" + (openId === g.id ? " selected" : "")}>
                <td>
                  <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
                    <span style={{ width: 30, height: 30, borderRadius: 9, background: "var(--accent-soft)", color: "var(--accent)", display: "grid", placeItems: "center", flexShrink: 0 }}>
                      <Icon name="group" size={15} />
                    </span>
                    <div>
                      <div style={{ fontWeight: 600 }}>{g.name}</div>
                      <div style={{ fontSize: 12, color: "var(--muted)" }}>{g.expires ? "Expires " + g.expires : "Owned by " + g.owner}</div>
                    </div>
                  </div>
                </td>
                <td className="mono">{g.members.toLocaleString()}</td>
                <td>
                  <SourceBadge source={g.source} />
                </td>
                <td className="hide-md">
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {g.roles.map((r) => (
                      <span className="chip" key={r}>
                        {roleName(r)}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="hide-md" style={{ color: "var(--muted)", fontSize: 12.5 }}>
                  {g.apps.join(", ")}
                </td>
                <td>
                  <Icon name="chevR" size={15} style={{ color: "var(--muted-2)" }} />
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", padding: "36px 0", color: "var(--muted)" }}>
                  No groups match your filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {openGroup && (
        <GroupDrawer
          group={openGroup}
          users={legacy.users}
          roles={legacy.roles}
          onUpdateGroup={legacyActions.updateGroup}
          onClose={() => setOpenId(null)}
          toast={A.toast}
        />
      )}
    </div>
  );
}
