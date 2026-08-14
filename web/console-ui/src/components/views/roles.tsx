"use client";

import { useState } from "react";
import { Icon } from "@/components/console/icons";
import { Avatar, ProtoBanner } from "@/components/console/primitives";
import { useConsole } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { PERM_ACTIONS, PERM_RESOURCES } from "@/lib/data-legacy";
import { PROTO_NOTES } from "@/lib/helpers";

export function RolesView() {
  const { legacy, legacyActions, A } = useConsole();
  const roles = legacy.roles;
  const users = legacy.users;
  const [sel, setSel] = useState(roles[0].id);
  const role = roles.find((r) => r.id === sel)!;
  const membersPreview = users.filter((u) => u.roles.includes(sel)).slice(0, 5);

  return (
    <div className="fade-in">
      <ProtoBanner>{PROTO_NOTES.roles}</ProtoBanner>
      <PageHead
        page="roles"
        sub="Roles bundle permissions. Assign them to users from the directory or via SCIM group mapping."
        actions={
          <>
            <button className="btn primary" onClick={() => A.toast("Custom role builder coming to this prototype on request", "key")}>
              <Icon name="plus" size={15} sw={2.4} />
              Create role
            </button>
          </>
        }
      />

      <div className="roles-grid">
        <div className="role-list">
          {roles.map((r) => {
            const on = sel === r.id;
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => setSel(r.id)}
                className="card"
                style={{
                  textAlign: "left",
                  cursor: "pointer",
                  padding: "13px 15px",
                  display: "flex",
                  alignItems: "center",
                  gap: 11,
                  borderColor: on ? "var(--accent)" : "var(--border-soft)",
                  boxShadow: on ? "0 0 0 3px var(--accent-soft)" : "var(--shadow-card)",
                  transition: "border-color 0.15s ease, box-shadow 0.15s ease",
                  font: "inherit",
                }}
              >
                <span
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 9,
                    flexShrink: 0,
                    display: "grid",
                    placeItems: "center",
                    background: on ? "var(--accent)" : "var(--accent-soft)",
                    color: on ? "#fff" : "var(--accent)",
                    transition: "all 0.15s ease",
                  }}
                >
                  <Icon name="key" size={15} />
                </span>
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 7, fontWeight: 600, fontSize: 13.5 }}>
                    {r.name}
                    {r.system && (
                      <span className="badge gray" style={{ fontSize: 10.5, padding: "2px 7px" }}>
                        System
                      </span>
                    )}
                  </span>
                  <span style={{ display: "block", fontSize: 12, color: "var(--muted)", marginTop: 1 }}>
                    {r.members.toLocaleString()} {r.members === 1 ? "member" : "members"}
                  </span>
                </span>
                <Icon name="chevR" size={15} style={{ color: on ? "var(--accent)" : "var(--muted-2)", flexShrink: 0 }} />
              </button>
            );
          })}
        </div>

        <div className="card" key={role.id}>
          <div className="card-pad" style={{ borderBottom: "1px solid var(--border-soft)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.01em" }}>{role.name}</span>
              {role.system && <span className="badge gray">System role</span>}
              <span style={{ marginLeft: "auto", display: "flex" }}>
                {membersPreview.map((m, i) => (
                  <span key={m.id} style={{ marginLeft: i ? -8 : 0, border: "2px solid var(--white)", borderRadius: "50%", display: "inline-flex" }}>
                    <Avatar name={m.name} size={26} />
                  </span>
                ))}
                {role.members > membersPreview.length && (
                  <span style={{ marginLeft: -8, width: 30, height: 30, borderRadius: "50%", background: "var(--field)", border: "2px solid var(--white)", display: "grid", placeItems: "center", fontSize: 10, fontWeight: 600, color: "var(--muted)" }}>
                    +{role.members - membersPreview.length}
                  </span>
                )}
              </span>
            </div>
            <p style={{ fontSize: 13, color: "var(--muted)", marginTop: 7, textWrap: "pretty", maxWidth: 560 }}>{role.desc}</p>
          </div>

          <div className="card-pad">
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 14 }}>
              <span className="card-title">Permissions</span>
              <span style={{ fontSize: 12, color: "var(--muted)" }}>{role.system ? "System roles are read-only — duplicate to customize." : "Click a cell to grant or revoke."}</span>
            </div>
            <table className="tbl" aria-label={`${role.name} permissions`} style={{ borderTop: "1px solid var(--border-soft)" }}>
              <thead>
                <tr>
                  <th scope="col" style={{ background: "transparent" }}>Resource</th>
                  {PERM_ACTIONS.map((a) => (
                    <th scope="col" key={a} style={{ background: "transparent", textAlign: "center", width: 76 }}>
                      {a}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {PERM_RESOURCES.map((res) => (
                  <tr key={res}>
                    <td style={{ fontWeight: 500 }}>{res}</td>
                    {PERM_ACTIONS.map((a) => {
                      const has = (role.perms[res] || []).includes(a);
                      const applicable = !(a === "export" && res !== "Audit Log");
                      return (
                        <td key={a} style={{ textAlign: "center" }}>
                          {applicable ? (
                            <button
                              type="button"
                              onClick={() => {
                                if (role.system) {
                                  A.toast("System roles can’t be edited — duplicate it first", "lock");
                                  return;
                                }
                                legacyActions.updateRolePerm(role.id, res, a, !has);
                                A.toast((has ? "Revoked " : "Granted ") + a + " on " + res);
                              }}
                              style={{
                                width: 26,
                                height: 26,
                                borderRadius: 8,
                                border: "none",
                                cursor: role.system ? "not-allowed" : "pointer",
                                display: "inline-grid",
                                placeItems: "center",
                                background: has ? "var(--accent-soft)" : "var(--border-soft)",
                                color: has ? "var(--accent)" : "var(--muted-2)",
                                transition: "all 0.13s ease",
                              }}
                              aria-label={a + " " + res + (has ? " granted" : " not granted")}
                            >
                              <Icon name={has ? "check" : "x"} size={12} sw={3} />
                            </button>
                          ) : (
                            <span style={{ color: "var(--muted-2)", fontSize: 12 }}>—</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ display: "flex", gap: 10, marginTop: 18 }}>
              <button className="btn ghost sm" onClick={() => A.toast("Duplicated as “" + role.name + " (copy)” — editable", "copy")}>
                <Icon name="copy" size={13} />
                Duplicate role
              </button>
              {!role.system && (
                <button className="btn danger-ghost sm" onClick={() => A.toast("Role deletion requires zero members", "alert")}>
                  <Icon name="x" size={13} />
                  Delete role
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
