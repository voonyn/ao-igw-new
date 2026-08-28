"use client";

import { useState } from "react";

import { Icon } from "../icons";
import { Modal } from "../primitives";
import { RecoveryCodesModal } from "./recovery-codes";

// The two changes a person makes to a Second Factor they already hold: remove
// it, or replace the Recovery Codes behind it.
//
// Both demand the current password in the body. The access token carries no
// session identifier and the gateway guard reads no store, so the password is
// the only proof the request can hold: without it, a leaked access token strips
// the account of its Second Factor in one request.
//
// One component runs both, because the prompt, the refusals and the busy state
// are identical. Only the address, the copy and the answer differ.
export type ManageMode = "remove" | "replace";

// The copy and the address of each mode, in one place.
const MODES: Record<ManageMode, {
  path: string;
  title: string;
  lede: string;
  submit: string;
  busy: string;
  danger: boolean;
}> = {
  remove: {
    path: "/api/account/mfa/totp/remove",
    title: "Remove two-step verification",
    lede: "Your authenticator and every recovery code stop working. You can set up a new authenticator afterwards. Your other devices stay signed in.",
    submit: "Remove",
    busy: "Removing…",
    danger: true,
  },
  replace: {
    path: "/api/account/mfa/totp/recovery-codes",
    title: "Replace recovery codes",
    lede: "We issue ten new codes and void every code you have now. The new ones are shown once.",
    submit: "Replace codes",
    busy: "Replacing…",
    danger: false,
  },
};

// MfaManageModal prompts for the password and runs the change.
//
// onDone runs after the change lands and, for a replacement, after the person
// says they saved the new codes. The page behind then re-reads the live state
// instead of guessing it.
export function MfaManageModal({
  mode,
  onClose,
  onDone,
}: {
  mode: ManageMode;
  onClose: () => void;
  onDone: () => void;
}) {
  const copy = MODES[mode];
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [reauth, setReauth] = useState(false);
  const [busy, setBusy] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);

  async function submit() {
    if (!password) {
      setError("Enter your current password.");
      return;
    }
    setError("");
    setReauth(false);
    setBusy(true);
    try {
      const res = await fetch(copy.path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        if (mode === "remove") {
          onDone();
          return;
        }
        setCodes(Array.isArray(data.recoveryCodes) ? data.recoveryCodes : []);
        return;
      }
      const code = data && data.error;
      setError(manageMessage(res.status, code));
      // Only a dead portal session offers the sign-in link. A wrong password
      // arrives as a 401 too, and it is retried in this modal.
      setReauth(res.status === 401 && (code === "unauthenticated" || code === "unauthorized"));
      setPassword("");
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  // The new codes are shown once. Saving them is the one exit that tells the
  // page behind to re-read the account.
  if (codes) {
    return (
      <RecoveryCodesModal
        title="Save your new recovery codes"
        lede="Store these somewhere safe. Your old codes no longer work. Each code signs you in once if you lose your authenticator, and they are not shown again."
        codes={codes}
        onSaved={onDone}
      />
    );
  }

  return (
    <Modal onClose={onClose}>
      <div className="drawer-head">
        <Icon name={mode === "remove" ? "shieldHalf" : "key"} size={18} sw={2} style={{ color: 'var(--accent)' }} />
        <span className="card-title">{copy.title}</span>
        <span style={{ marginLeft: 'auto' }}>
          <button type="button" className="icon-btn" onClick={onClose}><Icon name="x" size={18} /></button>
        </span>
      </div>

      <div className="drawer-body">
        <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 14, textWrap: 'pretty' }}>{copy.lede}</p>
        <label className="field-label" htmlFor="mfa-manage-password">Current password</label>
        <input
          id="mfa-manage-password"
          className="text-input"
          type="password"
          placeholder="••••••••"
          autoComplete="current-password"
          value={password}
          onChange={function (e) {
            setPassword(e.target.value);
            if (error) setError('');
          }}
        />
        {error && (
          <div style={{ marginTop: 10, fontSize: 13, color: 'var(--error)' }}>
            {error}
            {reauth && <> <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
          </div>
        )}
      </div>

      <div className="drawer-foot">
        <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={onClose} disabled={busy}>Cancel</button>
        <button
          type="button"
          className={'btn ' + (copy.danger ? 'danger-ghost' : 'primary')}
          style={{ flex: 1 }}
          onClick={submit}
          disabled={busy}
        >
          {busy ? copy.busy : copy.submit}
        </button>
      </div>
    </Modal>
  );
}

// manageMessage says why a change was refused. The view branches on the gateway
// slug, never on its message, so a reworded message never changes what is shown.
//
// invalid_credentials is the wrong password, and it arrives as a 401. It is read
// before the status, because a 401 here does not mean the portal session ended.
function manageMessage(status: number, code: unknown): string {
  if (code === "invalid_credentials") return "Current password is incorrect.";
  if (code === "no_active_factor") return "Two-step verification is already off for this account.";
  if (code === "invalid_input") return "Enter your current password.";
  if (status === 401) return "Your session is no longer valid.";
  if (status === 429) return "Too many attempts. Please wait a minute and try again.";
  if (status >= 500) return "The server is temporarily unavailable. Please try again in a moment.";
  return "Something went wrong. Please try again.";
}
