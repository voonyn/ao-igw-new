"use client";

import { useEffect, useState } from "react";
import { Icon } from "@/components/console/icons";
import { KeyStateBadge, MonoChip, Ts, UnbackedBtn, ViewNotice } from "@/components/console/primitives";
import { Modal } from "@/components/console/overlays";
import { useConsole } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { describeStatus } from "@/lib/console-api";
import { LABELS } from "@/lib/data";

const NO_KEY_WRITES = "Key rotation is a CLI/scheduled operation — it isn't driven from the console.";

/** The tenant's real published JWKS, read through the BFF (the gateway sets no CORS headers). */
function JwksModal({ onClose }: { onClose: () => void }) {
  const [state, setState] = useState<{ uri: string; jwks: unknown } | "loading" | "error">("loading");

  useEffect(() => {
    let alive = true;
    fetch("/api/jwks")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((d) => alive && setState({ uri: d.jwksUri, jwks: d.jwks }))
      .catch(() => alive && setState("error"));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <Modal title="Published JWKS" onClose={onClose} width={560}>
      <div className="drawer-head">
        <Icon name="key" size={18} style={{ color: "var(--accent)" }} />
        <div>
          <div style={{ fontWeight: 600, fontSize: 15 }}>Published JWKS</div>
          <div style={{ fontSize: 12, color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
            {typeof state === "object" ? state.uri : "resolving from discovery…"}
          </div>
        </div>
        <button type="button" className="icon-btn" style={{ marginLeft: "auto" }} aria-label="Close" onClick={onClose}>
          <Icon name="x" size={17} />
        </button>
      </div>
      <div style={{ padding: 20, overflow: "auto" }}>
        {state === "loading" && <div style={{ fontSize: 13, color: "var(--muted)" }}>Loading…</div>}
        {state === "error" && (
          <div style={{ fontSize: 13, color: "var(--danger)" }}>Couldn&apos;t read the JWKS from the provider.</div>
        )}
        {typeof state === "object" && <pre className="code-block">{JSON.stringify(state.jwks, null, 2)}</pre>}
      </div>
    </Modal>
  );
}

export function KeysView() {
  const { db, tenantId, A, status } = useConsole();
  const [jwksOpen, setJwksOpen] = useState(false);
  const keys = db.keys.filter((k) => k.tenantId === tenantId);
  const KU = LABELS.keyUse;
  // The keys read is instance-manager gated, so "no keys" and "not yours to see"
  // are different answers and must not render the same empty table.
  const failed = describeStatus(status.keys, "signing keys", "IAM_OWNER or IAM_ADMIN");

  return (
    <div className="fade-in">
      <PageHead
        page="keys"
        sub={
          <>
            Asymmetric key pairs for this tenant&apos;s provider. Public halves are served at the JWKS endpoint; the row ID doubles as the{" "}
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}>kid</span>.
          </>
        }
        actions={
          <>
            <button type="button" className="btn ghost" onClick={() => setJwksOpen(true)}>
              <Icon name="eye" size={15} />
              View JWKS
            </button>
            <UnbackedBtn reason={NO_KEY_WRITES} className="btn primary">
              <Icon name="refresh" size={15} sw={2.2} />
              Rotate now
            </UnbackedBtn>
          </>
        }
      />

      {failed ? (
        <ViewNotice title={failed.title} body={failed.body} onRetry={() => void A.reload()} />
      ) : (
      <div className="card" style={{ overflow: "auto hidden" }}>
        <table className="tbl" aria-label="Signing keys">
          <thead>
            <tr>
              <th scope="col">Key ID (kid)</th>
              <th scope="col">Use</th>
              <th scope="col">Algorithm</th>
              <th scope="col">Status</th>
              <th scope="col" className="hide-md">Signs from</th>
              <th scope="col" className="hide-md">Expires</th>
              {/* Last write to the row. Expires is a future grace deadline, so it is
                  this column — not that one — that says when a rotation moved the key. */}
              <th scope="col" className="hide-md">Last change</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id}>
                <td>
                  <MonoChip value={k.id} short toast={A.toast} />
                </td>
                <td>
                  <span className={"badge " + (k.use === 1 ? "accent" : "gray")}>{KU[k.use]}</span>
                </td>
                <td className="mono" style={{ color: "var(--ink)", fontWeight: 500 }}>
                  {k.alg}
                </td>
                <td>
                  <KeyStateBadge k={k} />
                </td>
                <td className="hide-md mono">
                  <Ts value={k.activeAt} />
                </td>
                <td className="hide-md mono">
                  <Ts value={k.expiresAt} empty="No expiry" />
                </td>
                <td className="hide-md mono">
                  <Ts value={k.updated} />
                </td>
              </tr>
            ))}
            {keys.length === 0 && (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", color: "var(--muted)", padding: 28 }}>
                  No signing keys for this tenant.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      )}

      <div className="card card-pad" style={{ marginTop: 14, display: "flex", gap: 12, alignItems: "flex-start" }}>
        <Icon name="lock" size={17} style={{ color: "var(--muted)", flexShrink: 0, marginTop: 1 }} />
        <p style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.55 }}>
          Private halves are PKCS8 DER, encrypted at the application layer before insert — the console never sees raw private key material.
        </p>
        <UnbackedBtn reason={NO_KEY_WRITES} className="btn sm ghost" wrapStyle={{ marginLeft: "auto", flexShrink: 0 }}>
          <Icon name="ban" size={13} />
          Retire oldest active
        </UnbackedBtn>
      </div>

      {jwksOpen && <JwksModal onClose={() => setJwksOpen(false)} />}
    </div>
  );
}
