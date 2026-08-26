"use client";

import { Icon } from "@/components/console/icons";
import { KV, Ts } from "@/components/console/primitives";
import { useConsole } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";

export function BootstrapView() {
  const { db, bootstrap: b } = useConsole();
  const tenant = b ? db.tenants.find((t) => t.id === b.tenantId) : db.tenants[0];
  if (!b) {
    return (
      <div className="fade-in">
        <PageHead
          page="bootstrap"
          sub="One-time, deployment-wide initialization."
        />
        <div className="card card-pad">No bootstrap record is available for this deployment.</div>
      </div>
    );
  }
  return (
    <div className="fade-in">
      <PageHead
        page="bootstrap"
        sub="One-time, deployment-wide initialization. The singleton row makes it run exactly once across the IAM lifecycle."
      />

      <div className="dash-row" style={{ alignItems: "start" }}>
        <div className="card">
          <div className="card-head">
            <span className="card-title">Created at bootstrap</span>
            <span className="spacer" />
            <span className="badge green">
              <Icon name="check" size={11} sw={3} />
              Applied
            </span>
          </div>
          <div className="card-pad" style={{ paddingTop: 12 }}>
            <div className="boot-list">
              {b.artifacts.length === 0 && (
                <p style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.55, margin: 0 }}>
                  Per-artifact provenance isn&apos;t recorded in phase 1 — the singleton record below confirms the
                  routine ran.
                </p>
              )}
              {b.artifacts.map((a) => (
                <div className="boot-row" key={a.label}>
                  <span className="bicon">
                    <Icon name="check" size={14} sw={2.6} />
                  </span>
                  <span className="blabel">{a.label}</span>
                  <span className="bdetail">{a.detail}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="card card-pad">
            <div className="sect-title">Singleton record</div>
            <KV k="id" v={<span style={{ fontFamily: "var(--font-mono)" }}>1 (CHECK id = 1)</span>} />
            <KV k="Default tenant" v={tenant ? tenant.name : b.tenantId} />
            <KV k="Routine version" v={<span style={{ fontFamily: "var(--font-mono)" }}>{b.version}</span>} />
            <KV k="Applied at" v={<Ts value={b.appliedAt} />} />
          </div>
          <div className="card card-pad">
            <div className="sect-title">Re-run</div>
            <p style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.55, margin: 0 }}>
              Bootstrap is a CLI operation (<span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>go run . bootstrap</span>) and is not
              invocable from the console. A second invocation hits the primary-key constraint and is refused atomically.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
