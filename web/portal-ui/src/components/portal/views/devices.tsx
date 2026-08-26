"use client";

import { useCallback, useEffect, useState } from "react";

import { Icon } from "../icons";
import { PageHead, AppLogo, NotWiredBanner } from "../primitives";
import { accountErrorFrom, appHue, appLetter, eventTime, type AccountErr } from "@/lib/format";
import { AOP } from "@/lib/portal-data";
import type { Actions, ConnectedAppWire } from "@/lib/types";

// AlphaOmega User Portal — Devices & Connected apps
//
// The connected-apps card is LIVE: it reads the caller's remembered OIDC consents
// from the account API through the BFF (/api/account/connected-apps → gateway
// /api/v1/account/connected-apps), which scopes them to the token `sub`. Revoking
// withdraws the consent AND kills the app's live tokens. Trusted devices remain
// placeholder — there is no device-trust concept in the backend to read.
export function DevicesView({ A }: { A: Actions }) {
  const d = AOP;
  const [devices, setDevices] = useState(d.devices);

  const [apps, setApps] = useState<ConnectedAppWire[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<AccountErr>("");
  // A 404 on the listing means the gateway sub-feature is not mounted → degrade to
  // a static "unavailable" line rather than surfacing a failure.
  const [unavailable, setUnavailable] = useState(false);
  const [confirming, setConfirming] = useState("");
  const [busy, setBusy] = useState("");

  function removeDevice(id: string) { setDevices(function (v) { return v.filter(function (x) { return x.id !== id; }); }); A.toast('Device removed'); }

  const loadApps = useCallback(async function () {
    try {
      const res = await fetch("/api/account/connected-apps", { headers: { Accept: "application/json" } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        setApps(Array.isArray(data) ? (data as ConnectedAppWire[]) : []);
        setErr(""); setUnavailable(false);
      } else if (res.status === 404) {
        setUnavailable(true);
      } else {
        setErr(accountErrorFrom(res.status, data && data.error));
      }
    } catch {
      setErr("error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(function () { void (async function () { await loadApps(); })(); }, [loadApps]);

  // revoke withdraws one app's access. A 404 means it was already revoked
  // elsewhere (another tab, another device), so the row is dropped and no error is
  // shown — the view reconciles rather than contradicting what the gateway says.
  async function revoke(clientId: string) {
    setBusy(clientId);
    setConfirming("");
    try {
      const res = await fetch("/api/account/connected-apps/" + encodeURIComponent(clientId), { method: "DELETE" });
      if (res.status === 200 || res.status === 404) {
        setApps(function (v) { return v.filter(function (x) { return x.clientId !== clientId; }); });
        setErr("");
        A.toast(res.status === 200 ? "Access revoked" : "That app was already disconnected");
        return;
      }
      const data = await res.json().catch(function () { return {}; });
      setErr(accountErrorFrom(res.status, data && data.error));
    } catch {
      setErr("error");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="fade-in">
      <PageHead title="Devices & Apps" sub="Manage the devices you trust and the third-party apps connected to your account." />
      <NotWiredBanner>Connected apps are live from your account&rsquo;s OAuth consents &mdash; revoking one cuts off its access immediately. Trusted devices below are still placeholder data: there is no device-trust API yet.</NotWiredBanner>

      {/* Trusted devices — NOT WIRED (no backing API) */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-head">
          <div>
            <span className="card-title">Trusted devices</span>
            <div className="card-sub">Devices that can skip extra verification when signing in.</div>
          </div>
        </div>
        <div className="card-pad" style={{ paddingTop: 10 }}>
          {devices.length === 0 ? (
            <div className="empty"><span className="e-icon"><Icon name="laptop" size={26} sw={2} /></span><div className="e-ttl">No trusted devices</div><div className="e-sub">Devices you mark as trusted will appear here.</div></div>
          ) : devices.map(function (v) {
            return (
              <div key={v.id} className="lrow">
                <span className="licon"><Icon name={v.icon} size={19} sw={2} /></span>
                <div className="lmain">
                  <div className="lttl">{v.name}{v.trusted && <span className="badge green"><Icon name="verified" size={11} sw={2} />Trusted</span>}</div>
                  <div className="lsub">{v.kind} · {v.os} · {v.loc} · {v.lastSeen}</div>
                </div>
                <span className="lend"><button type="button" className="btn sm danger-ghost" onClick={function () { removeDevice(v.id); }}><Icon name="trash" size={14} sw={2} /><span className="hide-md">Remove</span></button></span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Connected apps — LIVE via /api/account/connected-apps */}
      <div className="card">
        <div className="card-head">
          <div>
            <span className="card-title">Connected apps & services</span>
            <div className="card-sub">
              {loading || unavailable || err
                ? "Apps you have signed in to with AlphaOmega."
                : `${apps.length} app${apps.length === 1 ? '' : 's'} can access parts of your AlphaOmega account.`}
            </div>
          </div>
        </div>
        <div className="card-pad" style={{ paddingTop: 10 }}>
          {err && (
            <div style={{ marginBottom: 12, fontSize: 13, color: err === "reauth" ? "var(--error)" : "var(--warn)" }}>
              {err === "reauth" && <>Your session is no longer valid. <a href="/auth/login" style={{ color: "var(--accent)", fontWeight: 600 }}>Sign in again</a></>}
              {err === "rate" && "Too many requests. Please wait a minute and try again."}
              {err === "error" && "Could not load your connected apps. Please try again in a moment."}
            </div>
          )}
          {unavailable && <div style={{ fontSize: 13, color: "var(--muted)" }}>Connected-app management isn&rsquo;t available on this server.</div>}
          {!unavailable && loading && <div style={{ fontSize: 13, color: "var(--muted)" }}>Loading connected apps…</div>}
          {!unavailable && !loading && !err && apps.length === 0 && (
            <div className="empty"><span className="e-icon"><Icon name="link" size={26} sw={2} /></span><div className="e-ttl">No connected apps</div><div className="e-sub">When you sign in to other services with AlphaOmega, they&rsquo;ll show up here so you can review and revoke access.</div></div>
          )}
          {!unavailable && apps.map(function (a) {
            return (
              <div key={a.clientId} className="lrow">
                <AppLogo letter={appLetter(a.name)} hue={appHue(a.clientId)} size={40} />
                <div className="lmain">
                  <div className="lttl">{a.name}{a.active && <span className="badge green">Active</span>}</div>
                  <div className="lsub">Connected {eventTime(a.connectedAt)}</div>
                  {a.scopes.length > 0 && (
                    <div className="chip-row" style={{ marginTop: 7 }}>
                      {a.scopes.map(function (s) { return <span key={s} className="chip" style={{ fontSize: 11, padding: '2px 8px' }}>{s}</span>; })}
                    </div>
                  )}
                </div>
                {/* Revocation is irreversible (the app must be re-approved), so it
                    takes a second click rather than a modal. */}
                <span className="lend">
                  {confirming === a.clientId ? (
                    <>
                      <button type="button" className="btn sm ghost" onClick={function () { setConfirming(""); }}>Cancel</button>
                      <button type="button" className="btn sm danger" disabled={busy === a.clientId} onClick={function () { void revoke(a.clientId); }}>
                        {busy === a.clientId ? 'Revoking…' : 'Confirm'}
                      </button>
                    </>
                  ) : (
                    <button type="button" className="btn sm danger-ghost" disabled={busy === a.clientId} onClick={function () { setConfirming(a.clientId); }}>Revoke</button>
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
