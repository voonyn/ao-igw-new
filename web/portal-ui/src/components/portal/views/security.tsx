"use client";

import { useCallback, useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";

import { Icon } from "../icons";
import { useUser } from "../flow-context";
import { PageHead, SecurityRing, Modal, NotWiredBanner } from "../primitives";
import { accountErrorFrom, deviceIcon, deviceLabel, relTime, type AccountErr } from "@/lib/format";
import { deriveHealth } from "@/lib/health";
import { AOP } from "@/lib/portal-data";
import type { Actions, ActivityEventWire, Passkey } from "@/lib/types";
import { attestationToJSON, toCreationOptions } from "@/lib/webauthn";

// LiveSession mirrors the gateway dto.AccountSession returned by the BFF
// (/api/account/sessions). The `current` flag is not on the wire — the view
// derives it from currentSid (the ID-token `sid` the BFF supplies).
type LiveSession = {
  id: string;
  createdAt: string;
  expiresAt: string;
  state: number;
  // Recorded when the session was minted. There is no location: the gateway
  // resolves none, and a permanently empty field would read as "we do not know
  // where you signed in" rather than "we do not geolocate".
  ip: string;
  userAgent: string;
};

// One page of the caller's audit feed, read only to answer the "no failed
// sign-ins" health check. 100 is the largest page the account API serves.
const ACTIVITY_PAGE = 100;

// Security view, ported from portal/views-security.jsx. Password change is WIRED
// to the self-service account API (via the /api/account/password BFF route). The
// remaining actions (MFA/passkey enrolment, backup codes, session revocation)
// are still prototype interactions over placeholder data — no self-service API
// backs them yet.
export function SecurityView({ A }: { A: Actions }) {
  const d = AOP;
  // Password age/strength, recovery options and backup codes are still fixtures —
  // the score and the checklist beside them are not (see health below).
  const sec = d.security;
  const user = useUser();
  const [methods, setMethods] = useState(d.mfaMethods);
  // Active-session state is LIVE (self-service account API via the BFF); the rest
  // of this view is still placeholder data.
  const [sessions, setSessions] = useState<LiveSession[]>([]);
  const [currentSid, setCurrentSid] = useState('');
  const [sessionsLoading, setSessionsLoading] = useState(true);
  const [sessionsErr, setSessionsErr] = useState<AccountErr>('');
  const [sessionBusy, setSessionBusy] = useState(false);
  // Passkeys are LIVE (self-service account API via the BFF). An `unavailable`
  // error degrades the section to a static note when the sub-feature is not mounted.
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [pkLoading, setPkLoading] = useState(true);
  const [pkErr, setPkErr] = useState<AccountErr>('');
  const [pkBusy, setPkBusy] = useState(false);
  // Authenticator (TOTP) is LIVE (self-service account API via the BFF), degrading
  // to a static note the same way when the sub-feature is not mounted.
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [totpLoading, setTotpLoading] = useState(true);
  const [totpErr, setTotpErr] = useState<AccountErr>('');
  const [totpBusy, setTotpBusy] = useState(false);
  // One page of the caller's activity, read only so the score below counts the same
  // four checks Home does — a ring that scored three checks here and four there
  // would show two numbers for one account, which is what this derivation exists
  // to prevent. Never rendered as a timeline; that is the Activity view's job.
  const [activity, setActivity] = useState<ActivityEventWire[] | null>(null);
  const [activityErr, setActivityErr] = useState<AccountErr>('');
  const pkUnavailable = pkErr === 'unavailable';
  const totpUnavailable = totpErr === 'unavailable';
  // Enrol modal: the pending secret + otpauth URI (begin), the code being entered, the
  // one-time recovery codes (finish), and the modal's own inline error.
  const [totpEnroll, setTotpEnroll] = useState<{ secret: string; uri: string } | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpEnrollErr, setTotpEnrollErr] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  // Recovery-code replacement: how many are left (from the status response) and the
  // freshly issued set, shown once in its own modal.
  const [recoveryRemaining, setRecoveryRemaining] = useState(0);
  const [newRecoveryCodes, setNewRecoveryCodes] = useState<string[] | null>(null);
  const [recoveryErr, setRecoveryErr] = useState('');
  // Disable modal: the current code being entered + its inline error.
  const [totpDisableOpen, setTotpDisableOpen] = useState(false);
  const [totpDisableCode, setTotpDisableCode] = useState('');
  const [totpDisableErr, setTotpDisableErr] = useState('');
  const [pwModal, setPwModal] = useState(false);
  const [addMfa, setAddMfa] = useState(false);
  // Change-password form — wired to the self-service account API via the BFF
  // route (/api/account/password → gateway /api/v1/account/password).
  const [pwCurrent, setPwCurrent] = useState('');
  const [pwNext, setPwNext] = useState('');
  const [pwConfirm, setPwConfirm] = useState('');
  const [pwError, setPwError] = useState('');
  const [pwReauth, setPwReauth] = useState(false);
  const [pwBusy, setPwBusy] = useState(false);

  function closePwModal() {
    setPwModal(false);
    setPwCurrent(''); setPwNext(''); setPwConfirm('');
    setPwError(''); setPwReauth(false); setPwBusy(false);
  }

  async function submitPassword() {
    setPwError(''); setPwReauth(false);
    // Client-side guards before touching the BFF.
    if (pwNext !== pwConfirm) { setPwError("Passwords don't match."); return; }
    if (pwNext.length < 12) { setPwError('New password must be at least 12 characters.'); return; }
    setPwBusy(true);
    try {
      const res = await fetch('/api/account/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: pwCurrent, newPassword: pwNext }),
      });
      if (res.status === 200) {
        closePwModal();
        A.toast('Password changed', 'shield');
        return;
      }
      const data = await res.json().catch(function () { return {}; });
      // Gateway error codes (internal/api/http/response/api_error.go); the BFF
      // adds "unauthenticated" when no server-side token is available.
      const code = data && data.error;
      if (res.status === 401 && code === 'invalid_credentials') {
        setPwError('Current password is incorrect.');
      } else if (res.status === 400 && code === 'weak_password') {
        setPwError('That password is too weak or has appeared in a data breach. Choose a stronger one.');
      } else if (res.status === 400 && code === 'invalid_request') {
        setPwError('Please fill in every field.');
      } else if (res.status === 401 && (code === 'unauthenticated' || code === 'unauthorized')) {
        // Both codes mean re-auth: `unauthenticated` = no server-side token (BFF),
        // `unauthorized` = the gateway rejected the token (expired/rotated, or a
        // session predating the account audience). Retrying resends the same token
        // and 401s again, so offer a sign-in link instead of a generic error.
        setPwError('Your session is no longer valid.');
        setPwReauth(true);
      } else if (res.status === 429) {
        // Limiter tripped (gateway `rate_limited`) — advise waiting, not an
        // immediate retry. Button re-enables in `finally` so a later retry works.
        setPwError('Too many attempts. Please wait a minute and try again.');
      } else if (res.status >= 500) {
        // Upstream (BFF `upstream`/502) or gateway 500 — a transient problem,
        // not bad input, so don't blame the user's entry.
        setPwError('The server is temporarily unavailable. Please try again in a moment.');
      } else {
        setPwError('Something went wrong. Please try again.');
      }
    } catch {
      setPwError('Something went wrong. Please try again.');
    } finally {
      setPwBusy(false);
    }
  }

  // loadSessions fetches the caller's live sessions from the BFF, which forwards
  // the server-held bearer to the gateway and adds currentSid (the ID-token sid).
  const loadSessions = useCallback(async function () {
    try {
      const res = await fetch('/api/account/sessions', { headers: { Accept: 'application/json' } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        setSessions(Array.isArray(data.sessions) ? data.sessions : []);
        setCurrentSid(typeof data.currentSid === 'string' ? data.currentSid : '');
        setSessionsErr('');
      } else {
        setSessionsErr(accountErrorFrom(res.status, data && data.error));
      }
    } catch {
      setSessionsErr('error');
    } finally {
      setSessionsLoading(false);
    }
  }, []);

  // Fetch on mount inside an async IIFE so no setState runs synchronously in the
  // effect body (the writes happen after the awaited fetch, in a later microtask).
  useEffect(function () { void (async function () { await loadSessions(); })(); }, [loadSessions]);

  // endSession revokes one session; endOthers signs out every other session
  // (the current "This device" is preserved by the BFF via except=<sid>). Both
  // refresh the list on success and surface 401/429 like the password form.
  async function endSession(id: string) {
    setSessionBusy(true);
    try {
      const res = await fetch('/api/account/sessions/' + encodeURIComponent(id), { method: 'DELETE' });
      if (res.status === 200) {
        A.toast('Session signed out');
        await loadSessions();
        setSessionsErr('');
        return;
      }
      const data = await res.json().catch(function () { return {}; });
      setSessionsErr(accountErrorFrom(res.status, data && data.error));
    } catch {
      setSessionsErr('error');
    } finally {
      setSessionBusy(false);
    }
  }

  async function endOthers() {
    setSessionBusy(true);
    try {
      const res = await fetch('/api/account/sessions/revoke-others', { method: 'POST' });
      if (res.status === 200) {
        A.toast('Signed out everywhere else');
        await loadSessions();
        setSessionsErr('');
        return;
      }
      const data = await res.json().catch(function () { return {}; });
      setSessionsErr(accountErrorFrom(res.status, data && data.error));
    } catch {
      setSessionsErr('error');
    } finally {
      setSessionBusy(false);
    }
  }
  function enrollKey() {
    setMethods(function (m) { return m.map(function (x) { return x.id === 'm4' ? Object.assign({}, x, { empty: false, added: 'Just now', detail: 'Hardware security key' }) : x; }); });
    setAddMfa(false);
    A.toast('Security key enrolled', 'shield');
  }

  // loadPasskeys fetches the caller's live passkeys from the BFF (server-held bearer
  // forwarded to the gateway). A 404 maps to `unavailable` — the gateway sub-feature
  // is not mounted → degrade to a static section rather than surfacing an error.
  const loadPasskeys = useCallback(async function () {
    try {
      const res = await fetch('/api/account/passkeys', { headers: { Accept: 'application/json' } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        setPasskeys(Array.isArray(data.passkeys) ? data.passkeys : []);
        setPkErr('');
      } else {
        setPkErr(accountErrorFrom(res.status, data && data.error));
      }
    } catch {
      setPkErr('error');
    } finally {
      setPkLoading(false);
    }
  }, []);

  useEffect(function () { void (async function () { await loadPasskeys(); })(); }, [loadPasskeys]);

  // loadActivity reads one page of the caller's own audit feed. It feeds the health
  // derivation only, so a failure leaves that one check `unknown` (the score simply
  // counts three checks instead of four) rather than blanking the view.
  const loadActivity = useCallback(async function () {
    try {
      const res = await fetch('/api/account/activity?limit=' + ACTIVITY_PAGE, { headers: { Accept: 'application/json' } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        setActivity(Array.isArray(data.events) ? data.events : []);
        setActivityErr('');
      } else {
        setActivityErr(accountErrorFrom(res.status, data && data.error));
      }
    } catch {
      setActivityErr('error');
    }
  }, []);

  useEffect(function () { void (async function () { await loadActivity(); })(); }, [loadActivity]);

  // pkStatusErr maps a non-200 BFF/gateway response to the card's error state
  // (401 → re-login, 429 → wait, else generic), like the password form.
  async function pkStatusErr(res: Response) {
    const data = await res.json().catch(function () { return {}; });
    setPkErr(accountErrorFrom(res.status, data && data.error));
  }

  // enrollPasskey runs the browser WebAuthn ceremony end to end: begin (server
  // options) → navigator.credentials.create (OS prompt) → finish (attestation).
  async function enrollPasskey() {
    setPkErr('');
    if (typeof window === 'undefined' || !window.PublicKeyCredential) {
      setPkErr('error');
      return;
    }
    setPkBusy(true);
    try {
      const beginRes = await fetch('/api/account/passkeys/register/begin', { method: 'POST' });
      if (beginRes.status !== 200) { await pkStatusErr(beginRes); return; }
      const options = await beginRes.json();
      const cred = (await navigator.credentials.create({ publicKey: toCreationOptions(options) })) as PublicKeyCredential | null;
      if (!cred) { return; } // user dismissed the prompt — no error
      const label = deviceLabel(typeof navigator !== 'undefined' ? navigator.userAgent : '');
      const finishRes = await fetch('/api/account/passkeys/register/finish?name=' + encodeURIComponent(label), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: attestationToJSON(cred),
      });
      if (finishRes.status === 200) {
        setAddMfa(false);
        A.toast('Passkey added', 'shield');
        await loadPasskeys();
        return;
      }
      await pkStatusErr(finishRes);
    } catch (err) {
      // NotAllowedError = the user cancelled or the ceremony timed out — not a real
      // failure, so stay quiet; anything else is a generic error.
      if (!(err instanceof DOMException && err.name === 'NotAllowedError')) {
        setPkErr('error');
      }
    } finally {
      setPkBusy(false);
    }
  }

  // removePasskey deletes one passkey and refreshes the list on success. A 404 here
  // means that credential is already gone (another tab, another device) — NOT that
  // the sub-feature is unmounted, which is what the shared mapper would read it as.
  // Reconcile with the gateway instead of contradicting it.
  async function removePasskey(id: string) {
    setPkBusy(true);
    try {
      const res = await fetch('/api/account/passkeys/' + encodeURIComponent(id), { method: 'DELETE' });
      if (res.status === 200 || res.status === 404) {
        A.toast(res.status === 200 ? 'Passkey removed' : 'That passkey was already removed');
        await loadPasskeys();
        setPkErr('');
        return;
      }
      await pkStatusErr(res);
    } catch {
      setPkErr('error');
    } finally {
      setPkBusy(false);
    }
  }

  // loadTotpStatus fetches the caller's authenticator status from the BFF. A 404 maps
  // to `unavailable` — the sub-feature is not mounted → static section, like passkeys.
  const loadTotpStatus = useCallback(async function () {
    try {
      const res = await fetch('/api/account/totp', { headers: { Accept: 'application/json' } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        setTotpEnabled(Boolean(data.enabled));
        setRecoveryRemaining(Number(data.recoveryCodesRemaining) || 0);
        setTotpErr('');
      } else {
        setTotpErr(accountErrorFrom(res.status, data && data.error));
      }
    } catch {
      setTotpErr('error');
    } finally {
      setTotpLoading(false);
    }
  }, []);

  useEffect(function () { void (async function () { await loadTotpStatus(); })(); }, [loadTotpStatus]);

  // startTotpEnroll begins enrolment: fetch the pending secret + provisioning URI and
  // open the enrol modal. The caller's email rides along as the cosmetic ?account=
  // label for the authenticator entry (the gateway falls back to the token sub).
  async function startTotpEnroll() {
    setTotpErr(''); setTotpBusy(true);
    try {
      const q = user.email ? '?account=' + encodeURIComponent(user.email) : '';
      const res = await fetch('/api/account/totp/enroll/begin' + q, { method: 'POST' });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200 && typeof data.secret === 'string' && typeof data.otpauthUri === 'string') {
        setAddMfa(false);
        setTotpCode(''); setTotpEnrollErr(''); setRecoveryCodes(null);
        setTotpEnroll({ secret: data.secret, uri: data.otpauthUri });
        return;
      }
      if (res.status === 409) {
        // Already enrolled (e.g. another tab finished first) — reconcile and inform.
        A.toast('Authenticator already enrolled');
        await loadTotpStatus();
        return;
      }
      setTotpErr(accountErrorFrom(res.status, data && data.error));
    } catch {
      setTotpErr('error');
    } finally {
      setTotpBusy(false);
    }
  }

  function closeTotpEnroll() {
    setTotpEnroll(null); setTotpCode(''); setTotpEnrollErr(''); setRecoveryCodes(null);
  }

  // submitTotpFinish activates the factor with the entered code and, on success, shows
  // the one-time recovery codes in the same modal (they are never shown again).
  async function submitTotpFinish() {
    if (totpCode.length < 6) { setTotpEnrollErr('Enter the 6-digit code from your app.'); return; }
    setTotpEnrollErr(''); setTotpBusy(true);
    try {
      const res = await fetch('/api/account/totp/enroll/finish', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: totpCode }),
      });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200 && Array.isArray(data.recoveryCodes)) {
        setRecoveryCodes(data.recoveryCodes);
        setTotpEnabled(true);
        A.toast('Authenticator enabled', 'shield');
        return;
      }
      // 400 = wrong code (generic, no code-state oracle); 401/429 handled distinctly.
      if (res.status === 400) { setTotpEnrollErr("That code didn't match. Try again."); setTotpCode(''); }
      else if (res.status === 401) { setTotpEnrollErr('Your session is no longer valid — sign in again.'); }
      else if (res.status === 429) { setTotpEnrollErr('Too many attempts. Please wait a minute and try again.'); }
      else { setTotpEnrollErr('Something went wrong. Please try again.'); }
    } catch {
      setTotpEnrollErr('Something went wrong. Please try again.');
    } finally {
      setTotpBusy(false);
    }
  }

  // regenerateRecoveryCodes replaces the whole set: the gateway invalidates every
  // previous code atomically, so the returned set is the only one that works and it
  // is shown exactly once.
  async function regenerateRecoveryCodes() {
    setRecoveryErr(''); setTotpBusy(true);
    try {
      const res = await fetch('/api/account/totp/recovery-codes', { method: 'POST', headers: { Accept: 'application/json' } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200 && Array.isArray(data.recoveryCodes)) {
        setNewRecoveryCodes(data.recoveryCodes);
        await loadTotpStatus();
        return;
      }
      if (res.status === 401) { setRecoveryErr('Your session is no longer valid — sign in again.'); }
      else if (res.status === 429) { setRecoveryErr('Too many attempts. Please wait a minute and try again.'); }
      else { setRecoveryErr('Could not replace your recovery codes. Please try again.'); }
    } catch {
      setRecoveryErr('Could not replace your recovery codes. Please try again.');
    } finally {
      setTotpBusy(false);
    }
  }

  function openTotpDisable() { setTotpDisableOpen(true); setTotpDisableCode(''); setTotpDisableErr(''); }
  function closeTotpDisable() { setTotpDisableOpen(false); setTotpDisableCode(''); setTotpDisableErr(''); }

  // submitTotpDisable removes the factor after the user proves control with a current
  // TOTP code (or a recovery code) — the gateway verifies before removing.
  async function submitTotpDisable() {
    if (!totpDisableCode) { setTotpDisableErr('Enter a current code or a recovery code.'); return; }
    setTotpDisableErr(''); setTotpBusy(true);
    try {
      const res = await fetch('/api/account/totp', {
        method: 'DELETE', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: totpDisableCode }),
      });
      if (res.status === 200) {
        setTotpEnabled(false);
        closeTotpDisable();
        A.toast('Authenticator removed');
        await loadTotpStatus();
        return;
      }
      if (res.status === 400) { setTotpDisableErr("That code didn't match. Try again."); }
      else if (res.status === 401) { setTotpDisableErr('Your session is no longer valid — sign in again.'); }
      else if (res.status === 429) { setTotpDisableErr('Too many attempts. Please wait a minute and try again.'); }
      else { setTotpDisableErr('Something went wrong. Please try again.'); }
    } catch {
      setTotpDisableErr('Something went wrong. Please try again.');
    } finally {
      setTotpBusy(false);
    }
  }

  // The same derivation the Home dashboard rings, fed from the data this view
  // already loads plus the one activity page above — identical inputs, so the two
  // rings cannot report different numbers for the same account. A section that is
  // still loading or that failed passes null, which makes its check `unknown` and
  // drops it out of the score rather than counting it against the user.
  const health = deriveHealth({
    totpEnabled: totpLoading || totpErr ? null : totpEnabled,
    passkeys: pkLoading || pkErr ? null : passkeys,
    emailVerified: user.emailVerified,
    activity: activityErr ? null : activity,
    sessionCount: sessionsLoading || sessionsErr ? null : sessions.length,
  });
  const healthLoading = totpLoading || pkLoading || (activity === null && !activityErr);
  const failing = health.checks.filter(function (c) { return c.state === 'warn'; });

  const headline = healthLoading ? 'Checking your account…'
    : health.scored === 0 ? 'We couldn’t check your account'
      : health.score === 100 ? 'Your account is well protected'
        : health.score >= 50 ? 'Your account is mostly protected'
          : 'Your account needs attention';
  const headSub = healthLoading ? 'Reading your security settings.'
    : health.scored === 0 ? 'None of the security checks could run right now. Try again in a moment.'
      : failing.length === 0 ? 'All ' + health.scored + ' checks we can run are passing.'
        : health.passing + ' of ' + health.scored + ' checks passing — ' +
          failing.map(function (c) { return c.label.toLowerCase(); }).join(', ') + ' still ' +
          (failing.length === 1 ? 'needs' : 'need') + ' attention.';

  return (
    <div className="fade-in">
      <PageHead title="Security" sub="Protect your account with strong sign-in, two-factor methods and recovery options.">
        <button type="button" className="btn ghost" onClick={endOthers} disabled={sessionBusy}><Icon name="logout" size={15} sw={2} />Sign out everywhere</button>
      </PageHead>
      <NotWiredBanner>Your security score, password change, passkeys, authenticator apps (TOTP) and active-session management are live via the self-service account API. The two-factor methods list, recovery options, backup-code regeneration and SMS are still placeholder data with no self-service API yet — wire them when those surfaces land.</NotWiredBanner>

      {/* Score banner — LIVE: derived by lib/health.ts, the same function Home rings */}
      <div className="card card-pad" style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 22 }}>
        <SecurityRing score={health.score} size={96} stroke={9} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-display)', letterSpacing: '-0.01em' }}>{headline}</div>
          <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 3, textWrap: 'pretty' }}>{headSub}</div>
          <div className="chip-row" style={{ marginTop: 12 }}>
            {health.checks.map(function (c) {
              const tone = c.state === 'good' ? 'var(--success)' : c.state === 'warn' ? 'var(--warn)' : 'var(--muted)';
              return (
                <span key={c.id} className="chip">
                  <Icon name={c.state === 'good' ? 'check' : c.state === 'warn' ? 'alert' : 'clock'} size={12} sw={c.state === 'good' ? 3 : 2.4} style={{ color: tone }} />
                  {c.label}
                </span>
              );
            })}
          </div>
        </div>
      </div>

      <div className="col-2b">
        {/* Password */}
        <div className="card card-pad">
          <span className="sect-title"><Icon name="lock" size={13} sw={2} />Password</span>
          <div className="lrow" style={{ paddingTop: 6, borderBottom: 'none' }}>
            <span className="licon good"><Icon name="lock" size={18} sw={2} /></span>
            <div className="lmain">
              <div className="lttl">Password set <span className="badge green" style={{ marginLeft: 4 }}>{sec.passwordStrength}</span></div>
              <div className="lsub">Last changed {sec.passwordAgeDays} days ago</div>
            </div>
          </div>
          <button type="button" className="btn ghost" style={{ width: '100%', marginTop: 4 }} onClick={function () { setPwModal(true); }}>Change password</button>
        </div>

        {/* Recovery */}
        <div className="card card-pad">
          <span className="sect-title"><Icon name="refresh" size={13} sw={2} />Account recovery</span>
          <div style={{ marginTop: 4 }}>
            <div className="lrow" style={{ padding: '11px 0' }}>
              <span className="licon good"><Icon name="mail" size={17} sw={2} /></span>
              <div className="lmain"><div className="lttl">Recovery email</div><div className="lsub">m•••@gmail.com</div></div>
              <span className="lend"><span className="badge green"><span className="bdot"></span>Set</span></span>
            </div>
            <div className="lrow" style={{ padding: '11px 0' }}>
              <span className="licon good"><Icon name="phone" size={17} sw={2} /></span>
              <div className="lmain"><div className="lttl">Recovery phone</div><div className="lsub">••• ••• 0148</div></div>
              <span className="lend"><span className="badge green"><span className="bdot"></span>Set</span></span>
            </div>
            <div className="lrow" style={{ padding: '11px 0' }}>
              <span className="licon accent"><Icon name="key" size={17} sw={2} /></span>
              <div className="lmain"><div className="lttl">Backup codes</div><div className="lsub">{sec.backupCodes.remaining} of {sec.backupCodes.total} remaining</div></div>
              <span className="lend"><button type="button" className="btn sm ghost" onClick={function () { A.toast('New codes generated', 'download'); }}>Regenerate</button></span>
            </div>
          </div>
        </div>
      </div>

      {/* 2FA methods */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <div>
            <span className="card-title">Two-factor authentication</span>
            <div className="card-sub">Add a second step when signing in to keep your account secure.</div>
          </div>
          <span className="spacer"></span>
          <button type="button" className="btn primary sm" onClick={function () { setAddMfa(true); }}><Icon name="plus" size={14} sw={2.4} />Add method</button>
        </div>
        <div className="card-pad" style={{ paddingTop: 10 }}>
          {methods.map(function (m) {
            return (
              <div key={m.id} className="lrow">
                <span className={'licon ' + (m.empty ? '' : 'good')}><Icon name={m.icon} size={18} sw={2} /></span>
                <div className="lmain">
                  <div className="lttl">{m.name}{m.primary && <span className="badge accent">Primary</span>}</div>
                  <div className="lsub">{m.detail} · {m.added}</div>
                </div>
                <span className="lend">
                  {m.empty
                    ? <button type="button" className="btn sm ghost" onClick={function () { setAddMfa(true); }}>Enroll</button>
                    : <>
                        <span className="badge green hide-md"><span className="bdot"></span>Active</span>
                        <button type="button" className="btn sm danger-ghost" onClick={function () { A.toast(m.name + ' removed'); }}><Icon name="trash" size={14} sw={2} /></button>
                      </>}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Passkeys — LIVE via /api/account/passkeys */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <div>
            <span className="card-title">Passkeys</span>
            <div className="card-sub">Sign in with Face ID, Touch ID, a device PIN or a security key — no password needed.</div>
          </div>
          <span className="spacer"></span>
          {!pkUnavailable && (
            <button type="button" className="btn primary sm" onClick={enrollPasskey} disabled={pkBusy}>
              <Icon name="plus" size={14} sw={2.4} />{pkBusy ? 'Working…' : 'Add passkey'}
            </button>
          )}
        </div>
        <div className="card-pad" style={{ paddingTop: 10 }}>
          {pkUnavailable && (
            <div style={{ fontSize: 13, color: 'var(--muted)' }}>Passkey management is unavailable right now. Please try again later.</div>
          )}
          {!pkUnavailable && pkErr && (
            <div style={{ marginBottom: 10, fontSize: 13, color: pkErr === 'reauth' ? 'var(--error)' : 'var(--warn)' }}>
              {pkErr === 'reauth' && <>Your session is no longer valid. <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
              {pkErr === 'rate' && 'Too many attempts. Please wait a minute and try again.'}
              {pkErr === 'error' && 'Something went wrong with your passkey. Please try again.'}
            </div>
          )}
          {!pkUnavailable && pkLoading && <div style={{ fontSize: 13, color: 'var(--muted)' }}>Loading passkeys…</div>}
          {!pkUnavailable && !pkLoading && passkeys.length === 0 && !pkErr && (
            <div style={{ fontSize: 13, color: 'var(--muted)' }}>No passkeys yet. Add one to sign in without a password.</div>
          )}
          {!pkUnavailable && passkeys.map(function (p) {
            const used = p.lastUsedAt ? 'Last used ' + relTime(p.lastUsedAt) : 'Never used';
            return (
              <div key={p.id} className="lrow">
                <span className="licon good"><Icon name="fingerprint" size={18} sw={2} /></span>
                <div className="lmain">
                  <div className="lttl">{p.name || 'Passkey'}</div>
                  <div className="lsub">Added {relTime(p.createdAt)} · {used}</div>
                </div>
                <span className="lend">
                  <button type="button" className="btn sm danger-ghost" onClick={function () { removePasskey(p.id); }} disabled={pkBusy}><Icon name="trash" size={14} sw={2} /></button>
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Authenticator app (TOTP) — LIVE via /api/account/totp */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <div>
            <span className="card-title">Authenticator app</span>
            <div className="card-sub">Use time-based codes (TOTP) from an app like Google Authenticator, 1Password or Authy.</div>
          </div>
          <span className="spacer"></span>
          {!totpUnavailable && !totpEnabled && (
            <button type="button" className="btn primary sm" onClick={startTotpEnroll} disabled={totpBusy}>
              <Icon name="plus" size={14} sw={2.4} />{totpBusy ? 'Working…' : 'Set up'}
            </button>
          )}
        </div>
        <div className="card-pad" style={{ paddingTop: 10 }}>
          {totpUnavailable && (
            <div style={{ fontSize: 13, color: 'var(--muted)' }}>Authenticator management is unavailable right now. Please try again later.</div>
          )}
          {!totpUnavailable && totpErr && (
            <div style={{ marginBottom: 10, fontSize: 13, color: totpErr === 'reauth' ? 'var(--error)' : 'var(--warn)' }}>
              {totpErr === 'reauth' && <>Your session is no longer valid. <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
              {totpErr === 'rate' && 'Too many attempts. Please wait a minute and try again.'}
              {totpErr === 'error' && 'Something went wrong with your authenticator. Please try again.'}
            </div>
          )}
          {!totpUnavailable && totpLoading && <div style={{ fontSize: 13, color: 'var(--muted)' }}>Loading…</div>}
          {!totpUnavailable && !totpLoading && !totpEnabled && !totpErr && (
            <div style={{ fontSize: 13, color: 'var(--muted)' }}>No authenticator app yet. Set one up for a second step at sign-in.</div>
          )}
          {!totpUnavailable && !totpLoading && totpEnabled && (
            <div className="lrow">
              <span className="licon good"><Icon name="phone" size={18} sw={2} /></span>
              <div className="lmain">
                <div className="lttl">Authenticator app <span className="badge green hide-md"><span className="bdot"></span>Active</span></div>
                <div className="lsub">Time-based codes (TOTP)</div>
              </div>
              <span className="lend">
                <button type="button" className="btn sm danger-ghost" onClick={openTotpDisable} disabled={totpBusy}>Remove</button>
              </span>
            </div>
          )}
          {!totpUnavailable && !totpLoading && totpEnabled && (
            <div className="lrow">
              <span className={'licon ' + (recoveryRemaining <= 2 ? 'warn' : 'good')}><Icon name="key" size={18} sw={2} /></span>
              <div className="lmain">
                <div className="lttl">Recovery codes</div>
                <div className="lsub">
                  {recoveryRemaining} unused{recoveryRemaining <= 2 ? ' — replace them before you run out' : ''}
                </div>
              </div>
              <span className="lend">
                <button type="button" className="btn sm" onClick={regenerateRecoveryCodes} disabled={totpBusy}>
                  {totpBusy ? 'Working…' : 'Replace'}
                </button>
              </span>
            </div>
          )}
          {recoveryErr && <div style={{ marginTop: 10, fontSize: 13, color: 'var(--error)' }}>{recoveryErr}</div>}
        </div>
      </div>

      {/* Active sessions — LIVE via /api/account/sessions */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <div>
            <span className="card-title">Where you’re signed in</span>
            <div className="card-sub">{sessions.length} active session{sessions.length === 1 ? '' : 's'}</div>
          </div>
          <span className="spacer"></span>
          <button type="button" className="btn sm danger-ghost" onClick={endOthers} disabled={sessionBusy || sessions.length < 2}>Sign out others</button>
        </div>
        <div className="card-pad" style={{ paddingTop: 8 }}>
          {sessionsErr && (
            <div style={{ marginBottom: 10, fontSize: 13, color: sessionsErr === 'reauth' ? 'var(--error)' : 'var(--warn)' }}>
              {sessionsErr === 'reauth' && <>Your session is no longer valid. <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
              {sessionsErr === 'rate' && 'Too many attempts. Please wait a minute and try again.'}
              {sessionsErr === 'error' && 'Could not load your sessions. Please try again in a moment.'}
            </div>
          )}
          {sessionsLoading && <div style={{ fontSize: 13, color: 'var(--muted)' }}>Loading sessions…</div>}
          {!sessionsLoading && sessions.length === 0 && !sessionsErr && <div style={{ fontSize: 13, color: 'var(--muted)' }}>No other active sessions.</div>}
          {sessions.map(function (s) {
            const isCurrent = s.id === currentSid;
            const label = deviceLabel(s.userAgent);
            const where = [s.ip, 'Signed in ' + relTime(s.createdAt)].filter(Boolean).join(' · ');
            return (
              <div key={s.id} className="lrow">
                <span className="licon"><Icon name={deviceIcon(s.userAgent)} size={18} sw={2} /></span>
                <div className="lmain">
                  <div className="lttl">{label}{isCurrent && <span className="badge green">This device</span>}</div>
                  <div className="lsub">{where}</div>
                </div>
                <span className="lend">
                  {isCurrent
                    ? <span className="badge gray">Current</span>
                    : <button type="button" className="btn sm danger-ghost" onClick={function () { endSession(s.id); }} disabled={sessionBusy}>Sign out</button>}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Password modal */}
      {pwModal && (
        <Modal onClose={closePwModal}>
          <div className="drawer-head"><Icon name="lock" size={18} sw={2} style={{ color: 'var(--accent)' }} /><span className="card-title">Change password</span><span style={{ marginLeft: 'auto' }}><button type="button" className="icon-btn" onClick={closePwModal}><Icon name="x" size={18} /></button></span></div>
          <div className="drawer-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div><label className="field-label">Current password</label><input className="text-input" type="password" placeholder="••••••••" value={pwCurrent} onChange={function (e) { setPwCurrent(e.target.value); }} autoComplete="current-password" /></div>
              <div><label className="field-label">New password</label><input className="text-input" type="password" placeholder="At least 12 characters" value={pwNext} onChange={function (e) { setPwNext(e.target.value); }} autoComplete="new-password" /></div>
              <div><label className="field-label">Confirm new password</label><input className="text-input" type="password" placeholder="Re-enter new password" value={pwConfirm} onChange={function (e) { setPwConfirm(e.target.value); }} autoComplete="new-password" /></div>
            </div>
            {pwError && (
              <div style={{ marginTop: 12, fontSize: 13, color: 'var(--error)' }}>
                {pwError}
                {pwReauth && <> <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
              </div>
            )}
          </div>
          <div className="drawer-foot">
            <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={closePwModal} disabled={pwBusy}>Cancel</button>
            <button type="button" className="btn primary" style={{ flex: 1 }} onClick={submitPassword} disabled={pwBusy}>{pwBusy ? 'Updating…' : 'Update password'}</button>
          </div>
        </Modal>
      )}

      {/* Add MFA modal */}
      {addMfa && (
        <Modal onClose={function () { setAddMfa(false); }} width={440}>
          <div className="drawer-head"><Icon name="shield" size={18} sw={2} style={{ color: 'var(--accent)' }} /><span className="card-title">Add a second factor</span><span style={{ marginLeft: 'auto' }}><button type="button" className="icon-btn" onClick={function () { setAddMfa(false); }}><Icon name="x" size={18} /></button></span></div>
          <div className="drawer-body">
            {([
              { icon: 'fingerprint', ttl: 'Passkey', sub: 'Face ID, Touch ID or device PIN', rec: true, onSelect: enrollPasskey },
              { icon: 'phone', ttl: 'Authenticator app', sub: 'Time-based codes (TOTP)', onSelect: startTotpEnroll },
              { icon: 'key', ttl: 'Hardware security key', sub: 'YubiKey or FIDO2 key', onSelect: enrollPasskey },
              { icon: 'mail', ttl: 'SMS text message', sub: 'Codes sent to your phone', onSelect: enrollKey }
            ] as { icon: string; ttl: string; sub: string; rec?: boolean; onSelect: () => void }[]).map(function (o) {
              return (
                <button key={o.ttl} type="button" className="lrow" style={{ width: '100%', textAlign: 'left', cursor: 'pointer', border: 'none', background: 'transparent' }} onClick={o.onSelect} disabled={pkBusy}>
                  <span className="licon accent"><Icon name={o.icon} size={18} sw={2} /></span>
                  <div className="lmain"><div className="lttl">{o.ttl}{o.rec && <span className="badge accent">Recommended</span>}</div><div className="lsub">{o.sub}</div></div>
                  <span className="lend"><Icon name="arrowR" size={16} sw={2} style={{ color: 'var(--muted-2)' }} /></span>
                </button>
              );
            })}
          </div>
        </Modal>
      )}

      {/* Authenticator enrol modal — QR + code, then one-time recovery codes */}
      {totpEnroll && (
        <Modal onClose={closeTotpEnroll} width={440}>
          {recoveryCodes ? (
            <>
              <div className="drawer-head"><Icon name="key" size={18} sw={2} style={{ color: 'var(--accent)' }} /><span className="card-title">Save your recovery codes</span></div>
              <div className="drawer-body">
                <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 12, textWrap: 'pretty' }}>
                  Store these somewhere safe. Each code works <strong>once</strong> if you lose your authenticator — they won’t be shown again.
                </div>
                <ul style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, listStyle: 'none', margin: 0, padding: 14, borderRadius: 10, background: 'var(--surface-2, rgba(0,0,0,0.04))', fontFamily: 'monospace', fontSize: 14 }}>
                  {recoveryCodes.map(function (c) {
                    return <li key={c} style={{ textAlign: 'center', letterSpacing: '0.03em', userSelect: 'all' }}>{c}</li>;
                  })}
                </ul>
              </div>
              <div className="drawer-foot">
                <button type="button" className="btn primary" style={{ flex: 1 }} onClick={closeTotpEnroll}>I’ve saved my codes</button>
              </div>
            </>
          ) : (
            <>
              <div className="drawer-head"><Icon name="phone" size={18} sw={2} style={{ color: 'var(--accent)' }} /><span className="card-title">Set up authenticator app</span><span style={{ marginLeft: 'auto' }}><button type="button" className="icon-btn" onClick={closeTotpEnroll}><Icon name="x" size={18} /></button></span></div>
              <div className="drawer-body">
                <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 14, textWrap: 'pretty' }}>
                  Scan this QR code with your authenticator app, then enter the 6-digit code it shows.
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
                  <div style={{ background: '#fff', padding: 12, borderRadius: 12, border: '1.5px solid var(--border, #e5e7eb)' }}>
                    <QRCodeSVG value={totpEnroll.uri} size={168} marginSize={0} />
                  </div>
                  <div style={{ fontSize: 12.5, color: 'var(--muted)', textAlign: 'center' }}>
                    Can’t scan? Enter this key:{' '}
                    <span style={{ fontFamily: 'monospace', fontWeight: 600, letterSpacing: '0.03em', userSelect: 'all', color: 'var(--ink, inherit)' }}>{totpEnroll.secret}</span>
                  </div>
                </div>
                <div style={{ marginTop: 16 }}>
                  <label className="field-label">6-digit code</label>
                  <input
                    className="text-input"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    placeholder="123456"
                    value={totpCode}
                    onChange={function (e) { setTotpCode(e.target.value.replace(/\D/g, '')); if (totpEnrollErr) setTotpEnrollErr(''); }}
                  />
                </div>
                {totpEnrollErr && <div style={{ marginTop: 12, fontSize: 13, color: 'var(--error)' }}>{totpEnrollErr}</div>}
              </div>
              <div className="drawer-foot">
                <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={closeTotpEnroll} disabled={totpBusy}>Cancel</button>
                <button type="button" className="btn primary" style={{ flex: 1 }} onClick={submitTotpFinish} disabled={totpBusy}>{totpBusy ? 'Verifying…' : 'Turn on'}</button>
              </div>
            </>
          )}
        </Modal>
      )}

      {/* Replaced recovery codes — shown exactly once, like enrolment's set */}
      {newRecoveryCodes && (
        <Modal onClose={function () { setNewRecoveryCodes(null); }} width={440}>
          <div className="drawer-head"><Icon name="key" size={18} sw={2} style={{ color: 'var(--accent)' }} /><span className="card-title">Your new recovery codes</span></div>
          <div className="drawer-body">
            <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 12, textWrap: 'pretty' }}>
              Your previous codes no longer work. Store these somewhere safe — each works <strong>once</strong>, and they won’t be shown again.
            </div>
            <ul style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, listStyle: 'none', margin: 0, padding: 14, borderRadius: 10, background: 'var(--surface-2, rgba(0,0,0,0.04))', fontFamily: 'monospace', fontSize: 14 }}>
              {newRecoveryCodes.map(function (c) {
                return <li key={c} style={{ textAlign: 'center', letterSpacing: '0.03em', userSelect: 'all' }}>{c}</li>;
              })}
            </ul>
          </div>
          <div className="drawer-foot">
            <button type="button" className="btn primary" style={{ flex: 1 }} onClick={function () { setNewRecoveryCodes(null); }}>I’ve saved my codes</button>
          </div>
        </Modal>
      )}

      {/* Authenticator disable modal — requires a current code (Verify-then-Reset) */}
      {totpDisableOpen && (
        <Modal onClose={closeTotpDisable}>
          <div className="drawer-head"><Icon name="shield" size={18} sw={2} style={{ color: 'var(--error)' }} /><span className="card-title">Remove authenticator</span><span style={{ marginLeft: 'auto' }}><button type="button" className="icon-btn" onClick={closeTotpDisable}><Icon name="x" size={18} /></button></span></div>
          <div className="drawer-body">
            <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 14, textWrap: 'pretty' }}>
              Enter a current 6-digit code from your authenticator app, or one of your recovery codes, to turn it off.
            </div>
            <div>
              <label className="field-label">Current code</label>
              <input
                className="text-input"
                type="text"
                inputMode="text"
                autoComplete="one-time-code"
                placeholder="Code or recovery code"
                value={totpDisableCode}
                onChange={function (e) { setTotpDisableCode(e.target.value.trim()); if (totpDisableErr) setTotpDisableErr(''); }}
              />
            </div>
            {totpDisableErr && <div style={{ marginTop: 12, fontSize: 13, color: 'var(--error)' }}>{totpDisableErr}</div>}
          </div>
          <div className="drawer-foot">
            <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={closeTotpDisable} disabled={totpBusy}>Cancel</button>
            <button type="button" className="btn danger" style={{ flex: 1 }} onClick={submitTotpDisable} disabled={totpBusy}>{totpBusy ? 'Removing…' : 'Remove'}</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
