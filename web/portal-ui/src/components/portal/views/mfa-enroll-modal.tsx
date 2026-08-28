"use client";

import { useCallback, useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";

import { Icon } from "../icons";
import { Modal } from "../primitives";

// The three screens of one enrolment: the QR code, the code the Authenticator
// shows, and the Recovery Codes the gateway discloses exactly once.
//
// The start runs on mount. The gateway records no factor there, so a person who
// closes the modal before entering a code keeps the account they had.
type Stage =
  | { name: "loading" }
  | { name: "scan"; secret: string; otpauthUri: string }
  | { name: "codes"; codes: string[] }
  | { name: "failed"; message: string };

// How many digits the Authenticator shows. The gateway validates the same
// length, and this only stops a short value from reaching it.
const CODE_LENGTH = 6;

// MfaEnrollModal walks the person through adding an Authenticator.
//
// onEnrolled runs after the person saves the Recovery Codes, so the page behind
// re-reads the live state instead of guessing it.
export function MfaEnrollModal({ onClose, onEnrolled }: { onClose: () => void; onEnrolled: () => void }) {
  const [stage, setStage] = useState<Stage>({ name: "loading" });
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const start = useCallback(async function () {
    try {
      const res = await fetch("/api/account/mfa/totp/enroll/start", { method: "POST" });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200 && data.otpauthUri) {
        setStage({ name: "scan", secret: data.secret, otpauthUri: data.otpauthUri });
        return;
      }
      setStage({ name: "failed", message: startMessage(res.status, data && data.error) });
    } catch {
      setStage({ name: "failed", message: "Could not start setup. Please try again in a moment." });
    }
  }, []);

  // Start once on mount, inside an async IIFE so no setState runs synchronously
  // in the effect body.
  useEffect(function () { void (async function () { await start(); })(); }, [start]);

  async function activate() {
    if (code.length < CODE_LENGTH) {
      setError("Enter all " + CODE_LENGTH + " digits.");
      return;
    }
    setError("");
    setBusy(true);
    try {
      const res = await fetch("/api/account/mfa/totp/enroll/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200 && Array.isArray(data.recoveryCodes)) {
        setStage({ name: "codes", codes: data.recoveryCodes });
        return;
      }
      setError(activateMessage(res.status, data && data.error));
      setCode("");
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  // The Recovery Codes are shown once. Closing from here is the one exit that
  // tells the page behind to re-read the account.
  if (stage.name === "codes") {
    return (
      <Modal onClose={onEnrolled}>
        <div className="drawer-head">
          <Icon name="key" size={18} sw={2} style={{ color: 'var(--accent)' }} />
          <span className="card-title">Save your recovery codes</span>
        </div>
        <div className="drawer-body">
          <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 12, textWrap: 'pretty' }}>
            Store these somewhere safe. Each code signs you in <strong>once</strong> if you lose your
            authenticator, and they are not shown again.
          </p>
          <ul style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, listStyle: 'none', padding: 14, margin: 0, border: '1px solid var(--border)', borderRadius: 10, background: 'var(--field)', fontFamily: 'var(--font-mono)', fontSize: 14 }}>
            {stage.codes.map(function (c) {
              return <li key={c} style={{ textAlign: 'center', letterSpacing: '0.06em', userSelect: 'all' }}>{c}</li>;
            })}
          </ul>
        </div>
        <div className="drawer-foot">
          <button type="button" className="btn primary" style={{ flex: 1 }} onClick={onEnrolled}>I’ve saved my codes</button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal onClose={onClose}>
      <div className="drawer-head">
        <Icon name="shield" size={18} sw={2} style={{ color: 'var(--accent)' }} />
        <span className="card-title">Set up two-step verification</span>
        <span style={{ marginLeft: 'auto' }}>
          <button type="button" className="icon-btn" onClick={onClose}><Icon name="x" size={18} /></button>
        </span>
      </div>

      <div className="drawer-body">
        {stage.name === "failed" && <div style={{ fontSize: 13, color: 'var(--error)' }}>{stage.message}</div>}
        {stage.name === "loading" && <div style={{ fontSize: 13, color: 'var(--muted)' }}>Preparing your authenticator…</div>}

        {stage.name === "scan" && (
          <>
            <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 14, textWrap: 'pretty' }}>
              Scan this code with your authenticator app, then enter the 6-digit code it shows.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
              <div style={{ padding: 12, background: 'var(--white)', borderRadius: 12, border: '1px solid var(--border)' }}>
                <QRCodeSVG value={stage.otpauthUri} size={168} marginSize={0} />
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--muted)', textAlign: 'center' }}>
                Can’t scan? Enter this key:{" "}
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, letterSpacing: '0.04em', color: 'var(--ink)', userSelect: 'all' }}>{stage.secret}</span>
              </p>
            </div>

            <div style={{ marginTop: 16 }}>
              <label className="field-label" htmlFor="mfa-code">6-digit code</label>
              <input
                id="mfa-code"
                className="text-input"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                maxLength={CODE_LENGTH}
                value={code}
                onChange={function (e) {
                  setCode(e.target.value.replace(/\D/g, '').slice(0, CODE_LENGTH));
                  if (error) setError('');
                }}
                style={{ fontFamily: 'var(--font-mono)', letterSpacing: '0.35em', fontSize: 18 }}
              />
            </div>
            {error && <div style={{ marginTop: 10, fontSize: 13, color: 'var(--error)' }}>{error}</div>}
          </>
        )}
      </div>

      <div className="drawer-foot">
        <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={onClose} disabled={busy}>Cancel</button>
        <button
          type="button"
          className="btn primary"
          style={{ flex: 1 }}
          onClick={activate}
          disabled={busy || stage.name !== "scan"}
        >
          {busy ? 'Verifying…' : 'Turn on'}
        </button>
      </div>
    </Modal>
  );
}

// startMessage says why a start was refused. The view branches on the gateway
// slug, never on its message, so a reworded message never changes what is shown.
function startMessage(status: number, code: unknown): string {
  if (code === "mfa_already_enrolled") return "Two-step verification is already on for this account.";
  if (status === 401) return "Your session is no longer valid. Sign in again.";
  if (status === 429) return "Too many attempts. Please wait a minute and try again.";
  return "Could not start setup. Please try again in a moment.";
}

// activateMessage says why a code was refused.
//
// invalid_credentials is the wrong code, and it arrives as a 401. It is read
// before the status, because a 401 here does not mean the portal session ended.
function activateMessage(status: number, code: unknown): string {
  if (code === "invalid_credentials") return "That code is not right. Check your authenticator and try again.";
  if (code === "no_pending_enrolment") return "This setup expired. Close this and start again.";
  if (code === "invalid_input") return "Enter the 6-digit code your authenticator shows.";
  if (status === 401) return "Your session is no longer valid. Sign in again.";
  if (status === 429) return "Too many attempts. Please wait a minute and try again.";
  return "Something went wrong. Please try again.";
}
