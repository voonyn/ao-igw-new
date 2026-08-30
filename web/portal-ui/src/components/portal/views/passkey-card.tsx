"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";

import { Icon } from "../icons";
import { Modal } from "../primitives";
import { deviceLabel, relTime } from "@/lib/format";
import { browserPasskeyMessage, createPasskey, passkeyMessage, passkeysSupported } from "@/lib/webauthn";
import type { Actions } from "@/lib/types";

// PasskeyRow mirrors the gateway passkey.View returned by the BFF
// (/api/account/mfa/passkeys). The id is the public handle the browser names,
// never a credential. lastUsedAt is absent until the Passkey signs the person in
// once.
type PasskeyRow = {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
};

// PasskeyCard lists the Passkeys of the caller, adds one, renames one, and
// removes one.
//
// It sits beside the two-step block, so a person reads every Second Factor they
// hold on one screen.
//
// The removal demands the current password. The access token carries no session
// identifier and the gateway guard reads no store, so the password is the only
// proof the request can hold. A rename demands none: it destroys no Factor.
export function PasskeyCard({ A }: { A: Actions }) {
  const [rows, setRows] = useState<PasskeyRow[]>([]);
  const [loading, setLoading] = useState(true);
  // The message the card shows under the list. It is copy and not a class,
  // because each failure here says a different thing to a person.
  const [listErr, setListErr] = useState("");
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [addErr, setAddErr] = useState("");
  // The pending browser prompt. Closing the dialog aborts it, so a person who
  // changes their mind is not left with a browser sheet over a screen that moved
  // on.
  const ceremony = useRef<AbortController | null>(null);
  // The row one open dialog acts on. The whole row is held and not the id alone,
  // because both dialogs name the device the person is about to change.
  const [renaming, setRenaming] = useState<PasskeyRow | null>(null);
  const [removing, setRemoving] = useState<PasskeyRow | null>(null);

  // The feature check reads `window`, and the server renders no window. React
  // subscribes to it instead of an effect: the server answer enables the control,
  // and the browser answer replaces it right after hydration. Nothing changes it
  // after that, so the subscribe below has nothing to report.
  const supported = useSyncExternalStore(
    function () { return function () {}; }, passkeysSupported, function () { return true; });

  const load = useCallback(async function () {
    try {
      const res = await fetch("/api/account/mfa/passkeys", { headers: { Accept: "application/json" } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        setRows(Array.isArray(data) ? data : []);
        setListErr("");
      } else {
        setListErr(passkeyMessage(res.status, data && data.error));
      }
    } catch {
      setListErr("Could not load your passkeys. Please try again in a moment.");
    } finally {
      setLoading(false);
    }
  }, []);

  // Read on mount inside an async IIFE so no setState runs synchronously in the
  // effect body.
  useEffect(function () { void (async function () { await load(); })(); }, [load]);

  // Abort a prompt still open when the card unmounts.
  useEffect(function () { return function () { ceremony.current?.abort(); }; }, []);

  function openAdd() {
    // The default name is what the person would type anyway. They can replace it
    // before the prompt opens, and rename it later.
    setName(deviceLabel(navigator.userAgent));
    setAddErr("");
    setAdding(true);
  }

  function closeAdd() {
    ceremony.current?.abort();
    ceremony.current = null;
    setAdding(false);
    setBusy(false);
    setAddErr("");
  }

  // add runs the whole ceremony: ask the gateway for options, hand them to the
  // device, and send the answer back.
  //
  // The options and the answer cross this function whole. Every field of them is
  // covered by what the device signs, so nothing here reads inside either one.
  async function add() {
    setAddErr("");
    setBusy(true);
    const controller = new AbortController();
    ceremony.current = controller;
    try {
      const started = await fetch("/api/account/mfa/passkeys/register/start", { method: "POST" });
      const options = await started.json().catch(function () { return {}; });
      if (started.status !== 200 || !options.publicKey) {
        setAddErr(passkeyMessage(started.status, options && options.error));
        return;
      }

      const credential = await createPasskey(options.publicKey, controller.signal);

      const finished = await fetch("/api/account/mfa/passkeys/register/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential, name: name.trim() }),
      });
      if (finished.ok) {
        setAdding(false);
        A.toast("Passkey added", "key");
        await load();
        return;
      }
      const data = await finished.json().catch(function () { return {}; });
      setAddErr(passkeyMessage(finished.status, data && data.error));
    } catch (err) {
      // A cancelled prompt carries no message. The dialog stays open with the
      // name the person typed, and the button works again at once.
      setAddErr(browserPasskeyMessage(err));
    } finally {
      ceremony.current = null;
      setBusy(false);
    }
  }

  return (
    <div className="card card-pad" style={{ marginTop: 16 }}>
      <span className="sect-title"><Icon name="key" size={13} sw={2} />Passkeys</span>
      <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 4, textWrap: 'pretty' }}>
        A passkey signs you in with your fingerprint, your face, or your screen lock, instead of a code.
        Recovery codes cover your authenticator app alone. They do not sign you in with a passkey.
      </p>

      <div aria-live="polite" aria-busy={loading}>
        {loading && <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 10 }}>Loading passkeys…</div>}
        {!loading && rows.length === 0 && !listErr && (
          <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 10 }}>You have no passkeys yet.</div>
        )}
        {rows.map(function (row) {
          const used = row.lastUsedAt ? 'Last used ' + relTime(row.lastUsedAt) : 'Never used';
          return (
            <div key={row.id} className="lrow">
              <span className="licon good"><Icon name="fingerprint" size={18} sw={2} /></span>
              <div className="lmain">
                <div className="lttl">{row.name}</div>
                <div className="lsub">Added {relTime(row.createdAt)} · {used}</div>
              </div>
              <span className="lend">
                <button
                  type="button"
                  className="icon-btn"
                  aria-label={'Rename ' + row.name}
                  onClick={function () { setRenaming(row); }}
                >
                  <Icon name="edit" size={16} sw={2} />
                </button>
                <button
                  type="button"
                  className="icon-btn"
                  aria-label={'Remove ' + row.name}
                  onClick={function () { setRemoving(row); }}
                >
                  <Icon name="trash" size={16} sw={2} />
                </button>
              </span>
            </div>
          );
        })}
        {listErr && <div style={{ marginTop: 10, fontSize: 13, color: 'var(--warn)' }}>{listErr}</div>}
      </div>

      {/* The control is always rendered. A browser with no support gets it
          disabled and the reason under it, because a person who sees no control
          cannot tell a missing feature from a broken page. */}
      <button
        type="button"
        className="btn ghost"
        style={{ width: '100%', marginTop: 10 }}
        onClick={openAdd}
        disabled={!supported}
        aria-describedby={supported ? undefined : "passkey-unsupported"}
      >
        <Icon name="plus" size={15} sw={2} />Add a passkey
      </button>
      {!supported && (
        <div id="passkey-unsupported" style={{ marginTop: 6, fontSize: 12.5, color: 'var(--muted)' }}>
          This browser does not support passkeys. Try a current Chrome, Edge, Safari, or Firefox.
        </div>
      )}

      {adding && (
        <Modal onClose={closeAdd}>
          <div className="drawer-head">
            <Icon name="key" size={18} sw={2} style={{ color: 'var(--accent)' }} />
            <span className="card-title">Add a passkey</span>
            <span style={{ marginLeft: 'auto' }}>
              <button type="button" className="icon-btn" onClick={closeAdd}><Icon name="x" size={18} /></button>
            </span>
          </div>
          <div className="drawer-body">
            <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 14, textWrap: 'pretty' }}>
              Name this passkey so you recognise it later, then follow the prompt from your browser.
            </p>
            <label className="field-label" htmlFor="passkey-name">Name</label>
            <input
              id="passkey-name"
              className="text-input"
              maxLength={255}
              value={name}
              placeholder="My laptop"
              onChange={function (e) { setName(e.target.value); if (addErr) setAddErr(''); }}
            />
            <div aria-live="polite">
              {addErr && <div style={{ marginTop: 10, fontSize: 13, color: 'var(--error)' }}>{addErr}</div>}
            </div>
          </div>
          <div className="drawer-foot">
            <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={closeAdd}>Cancel</button>
            <button type="button" className="btn primary" style={{ flex: 1 }} onClick={add} disabled={busy}>
              {busy ? 'Waiting for your device…' : 'Add passkey'}
            </button>
          </div>
        </Modal>
      )}

      {renaming && (
        <RenamePasskeyModal
          row={renaming}
          onClose={function () { setRenaming(null); }}
          onDone={async function () {
            setRenaming(null);
            A.toast("Passkey renamed", "key");
            await load();
          }}
        />
      )}

      {removing && (
        <RemovePasskeyModal
          row={removing}
          onClose={function () { setRemoving(null); }}
          onDone={async function () {
            setRemoving(null);
            A.toast("Passkey removed", "key");
            await load();
          }}
        />
      )}
    </div>
  );
}

// RenamePasskeyModal writes a new name onto one Passkey.
//
// It asks for no password. A rename destroys no Factor and changes no key, so
// the proof the removal demands would only cost the person a step here.
//
// Two Passkeys may share a name. Two devices a person calls "Phone" are their
// own business, and nothing here refuses it.
function RenamePasskeyModal({
  row,
  onClose,
  onDone,
}: {
  row: PasskeyRow;
  onClose: () => void;
  onDone: () => void;
}) {
  const [name, setName] = useState(row.name);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function save() {
    const next = name.trim();
    if (!next) {
      setError("Enter a name for this passkey.");
      return;
    }
    setError("");
    setBusy(true);
    try {
      const res = await fetch("/api/account/mfa/passkeys/" + encodeURIComponent(row.id), {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: next }),
      });
      if (res.ok) {
        onDone();
        return;
      }
      const data = await res.json().catch(function () { return {}; });
      setError(passkeyMessage(res.status, data && data.error));
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal onClose={onClose}>
      <div className="drawer-head">
        <Icon name="edit" size={18} sw={2} style={{ color: 'var(--accent)' }} />
        <span className="card-title">Rename passkey</span>
        <span style={{ marginLeft: 'auto' }}>
          <button type="button" className="icon-btn" onClick={onClose}><Icon name="x" size={18} /></button>
        </span>
      </div>
      <div className="drawer-body">
        <label className="field-label" htmlFor="passkey-rename">Name</label>
        <input
          id="passkey-rename"
          className="text-input"
          maxLength={255}
          value={name}
          placeholder="My laptop"
          onChange={function (e) { setName(e.target.value); if (error) setError(''); }}
        />
        <div aria-live="polite">
          {error && <div style={{ marginTop: 10, fontSize: 13, color: 'var(--error)' }}>{error}</div>}
        </div>
      </div>
      <div className="drawer-foot">
        <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={onClose} disabled={busy}>Cancel</button>
        <button type="button" className="btn primary" style={{ flex: 1 }} onClick={save} disabled={busy}>
          {busy ? 'Saving…' : 'Save name'}
        </button>
      </div>
    </Modal>
  );
}

// RemovePasskeyModal names the device and takes the current password.
//
// The copy names the device, because a person who holds several must know which
// one is about to go. It also states what happens when this was the last Second
// Factor: the next sign-in asks for enrolment, which is where a person with no
// Factor belongs.
function RemovePasskeyModal({
  row,
  onClose,
  onDone,
}: {
  row: PasskeyRow;
  onClose: () => void;
  onDone: () => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [reauth, setReauth] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!password) {
      setError("Enter your current password.");
      return;
    }
    setError("");
    setReauth(false);
    setBusy(true);
    try {
      const res = await fetch("/api/account/mfa/passkeys/" + encodeURIComponent(row.id) + "/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (res.ok) {
        onDone();
        return;
      }
      const data = await res.json().catch(function () { return {}; });
      const code = data && data.error;
      setError(passkeyMessage(res.status, code));
      // Only a dead portal session offers the sign-in link. A wrong password
      // arrives as a 401 too, and it is retried in this dialog.
      setReauth(res.status === 401 && (code === "unauthenticated" || code === "unauthorized"));
      setPassword("");
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal onClose={onClose}>
      <div className="drawer-head">
        <Icon name="trash" size={18} sw={2} style={{ color: 'var(--accent)' }} />
        <span className="card-title">Remove passkey</span>
        <span style={{ marginLeft: 'auto' }}>
          <button type="button" className="icon-btn" onClick={onClose}><Icon name="x" size={18} /></button>
        </span>
      </div>
      <div className="drawer-body">
        <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 14, textWrap: 'pretty' }}>
          <strong style={{ color: 'var(--text)' }}>{row.name}</strong> stops signing you in. Do this when you
          no longer have the device. If this was your last second factor, your next sign-in asks you to set
          one up again.
        </p>
        <label className="field-label" htmlFor="passkey-remove-password">Current password</label>
        <input
          id="passkey-remove-password"
          className="text-input"
          type="password"
          maxLength={72}
          placeholder="••••••••"
          autoComplete="current-password"
          value={password}
          onChange={function (e) { setPassword(e.target.value); if (error) setError(''); }}
        />
        <div aria-live="polite">
          {error && (
            <div style={{ marginTop: 10, fontSize: 13, color: 'var(--error)' }}>
              {error}
              {reauth && <> <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
            </div>
          )}
        </div>
      </div>
      <div className="drawer-foot">
        <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={onClose} disabled={busy}>Cancel</button>
        <button type="button" className="btn danger-ghost" style={{ flex: 1 }} onClick={submit} disabled={busy}>
          {busy ? 'Removing…' : 'Remove passkey'}
        </button>
      </div>
    </Modal>
  );
}
