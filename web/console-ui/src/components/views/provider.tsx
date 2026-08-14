"use client";

import { useEffect, useState } from "react";
import { Btn, Field, FutureTag, Toggle, ViewNotice } from "@/components/console/primitives";
import { useConsole, usePending } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { describeStatus, providerApi } from "@/lib/console-api";
import type { ProviderConfig, ProviderConfigBody } from "@/lib/types";

type NumericKey = "authCodeLifetime" | "accessTokenLifetime" | "idTokenLifetime" | "refreshTokenLifetime";

// The writable knobs, in body-field order. Everything else on this page —
// issuer, state, access-token format, signing algorithms — is read-only by
// design: the API refuses writes to them (changing the issuer 401s every
// outstanding admin token, including the operator's own).
const NUMERIC_KEYS: NumericKey[] = ["authCodeLifetime", "accessTokenLifetime", "idTokenLifetime", "refreshTokenLifetime"];

// A lifetime of 0 is not "off" anywhere downstream — the server turns it back
// into a default — so it is refused there, and the inputs say so here.
const MIN_LIFETIME = 1;
const MAX_LIFETIME = 31536000; // one year

/** The changed fields between the loaded config and the draft, or null when a
 * value is out of range. An unchanged field is omitted so the PATCH leaves it
 * alone. */
function diffBody(loaded: ProviderConfig, draft: ProviderConfig): ProviderConfigBody | null {
  const body: ProviderConfigBody = {};
  for (const k of NUMERIC_KEYS) {
    const v = draft[k];
    if (v == null || v === loaded[k]) continue;
    if (!Number.isInteger(v) || v < MIN_LIFETIME || v > MAX_LIFETIME) return null;
    body[k] = v;
  }
  if (draft.requirePkce !== loaded.requirePkce) body.requirePkce = draft.requirePkce;
  if (draft.refreshRotation !== loaded.refreshRotation) body.refreshRotation = draft.refreshRotation;
  return body;
}

export function ProviderView() {
  const { db, tenantId, A, status } = useConsole();
  const pc = db.providerConfigs[tenantId];
  const [draft, setDraft] = useState<ProviderConfig | undefined>(pc);
  const [saving, run] = usePending();
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDraft(db.providerConfigs[tenantId]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  const body = pc && draft ? diffBody(pc, draft) : null;
  const dirty = body !== null && Object.keys(body).length > 0;

  async function save() {
    if (!body || !dirty) return;
    // No `after`: the default reload is exactly what this needs — the saved row
    // is re-read into the shared console data.
    await run(() => providerApi.update(body), { ok: "Provider settings saved" });
  }

  // "Refused" and "not configured" are different answers, and neither is "empty".
  const failed = describeStatus(status.provider, "provider settings", "IAM_OWNER or IAM_ADMIN");
  if (failed || !draft) {
    return (
      <div className="fade-in">
        <PageHead
          page="provider"
        />
        {failed ? (
          <ViewNotice title={failed.title} body={failed.body} onRetry={() => void A.reload()} />
        ) : (
          <ViewNotice title="No provider config for this tenant." body="The OIDC provider has not been configured on this tenant yet." icon="settings" />
        )}
      </div>
    );
  }

  function field(label: string, key: NumericKey, suffix?: string) {
    const d = draft as ProviderConfig;
    return (
      <div>
        <Field label={<>{label}</>}>
          <input
            className="text-input"
            type="number"
            min={MIN_LIFETIME}
            max={MAX_LIFETIME}
            value={d[key] == null ? "" : (d[key] as number)}
            placeholder="disabled"
            onChange={(e) => setDraft({ ...d, [key]: e.target.value === "" ? null : Number(e.target.value) })}
          />
        </Field>
        {suffix && <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 4 }}>{suffix}</div>}
      </div>
    );
  }

  return (
    <div className="fade-in">
      <PageHead
        page="provider"
        sub={
          <>
            Drives <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}>/.well-known/openid-configuration</span> and the runtime defaults the authorization server enforces.
          </>
        }
        actions={
          <Btn className="btn primary" pending={saving} disabled={!dirty} onClick={() => void save()}>
            Save changes
          </Btn>
        }
      />

      {/* A disabled Save is otherwise ambiguous between "nothing changed" and
          "a value is out of range" — say which. */}
      {body === null && (
        <div className="card card-pad" style={{ marginBottom: 14, fontSize: 12.5, color: "var(--danger, var(--muted))" }}>
          Every lifetime must be a whole number between {MIN_LIFETIME} and {MAX_LIFETIME} seconds. 0 is not
          &ldquo;disabled&rdquo; — the server treats it as unset and falls back to its own default, so it is refused.
        </div>
      )}

      <div className="dash-row" style={{ alignItems: "start" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="card card-pad">
            <div className="sect-title">Issuer</div>
            <div className="form-grid">
              <div className="full">
                <Field label="Issuer URL">
                  <input
                    className="text-input"
                    style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}
                    value={draft.issuer}
                    readOnly
                  />
                </Field>
                <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 4 }}>
                  Read-only. Changing the issuer invalidates every token already issued for this tenant — including the one this console is using — so it is not editable here.
                </div>
              </div>
            </div>
            <div className="kv" style={{ marginTop: 12 }}>
              <span className="k" style={{ color: "var(--ink)", fontWeight: 500 }}>
                Require PKCE (S256)
                <span style={{ display: "block", fontSize: 11.5, color: "var(--muted)", fontWeight: 400, marginTop: 2 }}>Authorization-code flows must carry a code challenge.</span>
              </span>
              <Toggle on={draft.requirePkce} label="Require PKCE" onChange={(v) => setDraft({ ...draft, requirePkce: v })} />
            </div>
            <div className="kv">
              <span className="k" style={{ color: "var(--ink)", fontWeight: 500 }}>
                Rotate refresh tokens on use
                <span style={{ display: "block", fontSize: 11.5, color: "var(--muted)", fontWeight: 400, marginTop: 2 }}>Each redemption replaces the token; reuse of an old one is detected.</span>
              </span>
              <Toggle on={draft.refreshRotation} label="Refresh rotation" onChange={(v) => setDraft({ ...draft, refreshRotation: v })} />
            </div>
          </div>

          <div className="card card-pad">
            <div className="sect-title">Token lifetimes</div>
            <div className="form-grid">
              {field("Authorization code (secs)", "authCodeLifetime")}
              {field("Access token (secs)", "accessTokenLifetime")}
              {field("ID token (secs)", "idTokenLifetime")}
              {field("Refresh token (secs)", "refreshTokenLifetime", "Empty means unset. Clearing it back to unset is not supported here — set a lifetime and it stays set.")}
            </div>
          </div>
        </div>

        <div className="card card-pad">
          <div className="sect-title">
            Advertised signing algorithms <FutureTag label="Editing coming soon" />
          </div>
          <p style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 12 }}>
            Published in discovery metadata. Stored as a grouped JSON blob; per-algorithm editing isn&apos;t wired yet.
          </p>
          {Object.keys(draft.signingAlgs).map((k) => {
            const algs = draft.signingAlgs[k];
            return (
              <div className="kv" key={k}>
                <span className="k">{k}</span>
                <span className="v chip-row" style={{ justifyContent: "flex-end" }}>
                  {algs.length ? (
                    algs.map((a) => (
                      <span key={a} className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                        {a}
                      </span>
                    ))
                  ) : (
                    <span style={{ color: "var(--muted-2)" }}>—</span>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
