"use client";

import { useCallback, useEffect, useState } from "react";

import { Icon } from "../icons";
import { useUser } from "../flow-context";
import { PageHead, SecurityRing, Modal, NotWiredBanner } from "../primitives";
import { MfaEnrollModal } from "./mfa-enroll-modal";
import { accountErrorFrom, deviceIcon, deviceLabel, relTime, type AccountErr } from "@/lib/format";
import { deriveHealth } from "@/lib/health";
import { AOP } from "@/lib/portal-data";
import type { Actions, ActivityEventWire } from "@/lib/types";

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

// MfaState mirrors the gateway dto.StatusResponse returned by the BFF
// (/api/account/mfa). It carries no secret and no code: the gateway sends
// neither, because a page that states whether a factor is on needs neither.
type MfaState = {
  active: boolean;
  // Absent while no factor is active.
  activatedAt?: string;
  recoveryCodesRemaining: number;
};

// One page of the caller's audit feed, read only to answer the "no failed
// sign-ins" health check. 100 is the largest page the account API serves.
const ACTIVITY_PAGE = 100;

// Security view, ported from portal/views-security.jsx. Password change,
// active-session management and two-step verification are WIRED to the
// self-service account API (via the /api/account/* BFF routes). Password
// age/strength and the recovery options are still placeholder data — no
// self-service API backs them.
// mfaSubtext says what the card knows. A failed read says nothing about the
// account: a card that read "off" because the endpoint failed would invite a
// person to enrol a factor they already hold.
function mfaSubtext(state: MfaState | null, err: AccountErr): string {
  if (err) return 'We couldn’t check this right now';
  if (!state) return 'Checking…';
  if (!state.active) return 'Add a code from your authenticator app when you sign in';
  const left = state.recoveryCodesRemaining;
  return 'Added ' + relTime(state.activatedAt ?? '') + ' · ' +
    left + ' recovery code' + (left === 1 ? '' : 's') + ' left';
}

export function SecurityView({ A }: { A: Actions }) {
  const d = AOP;
  // Password age/strength and recovery options are still fixtures — the score and
  // the checklist beside them are not (see health below).
  const sec = d.security;
  const user = useUser();
  // Active-session state is LIVE (self-service account API via the BFF).
  const [sessions, setSessions] = useState<LiveSession[]>([]);
  const [currentSid, setCurrentSid] = useState('');
  const [sessionsLoading, setSessionsLoading] = useState(true);
  const [sessionsErr, setSessionsErr] = useState<AccountErr>('');
  const [sessionBusy, setSessionBusy] = useState(false);
  // One page of the caller's activity, read only so the score below counts the same
  // checks Home does — a ring that scored one check here and two there would show
  // two numbers for one account, which is what this derivation exists to prevent.
  // Never rendered as a timeline; that is the Activity view's job.
  const [activity, setActivity] = useState<ActivityEventWire[] | null>(null);
  const [activityErr, setActivityErr] = useState<AccountErr>('');
  // Two-step verification state is LIVE (self-service account API via the BFF).
  // null means "not read yet"; a failed read leaves it null and the card says so.
  const [mfa, setMfa] = useState<MfaState | null>(null);
  const [mfaErr, setMfaErr] = useState<AccountErr>('');
  const [mfaModal, setMfaModal] = useState(false);
  const [pwModal, setPwModal] = useState(false);
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
      } else if ((res.status === 400 || res.status === 422) && code === 'invalid_input') {
        // The gateway validates the body and answers one slug for both statuses:
        // 422 names the fields that failed, and 400 means the body did not parse.
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

  // loadActivity reads one page of the caller's own audit feed. It feeds the health
  // derivation only, so a failure leaves that one check `unknown` (the score simply
  // counts one check instead of two) rather than blanking the view.
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

  // loadMfa reads the live second-factor state of the caller. The card renders
  // exactly what this returns, including the remaining Recovery Code count, so
  // nothing on it is derived from a fixture.
  const loadMfa = useCallback(async function () {
    try {
      const res = await fetch('/api/account/mfa', { headers: { Accept: 'application/json' } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        setMfa({
          active: Boolean(data.active),
          activatedAt: typeof data.activatedAt === 'string' ? data.activatedAt : undefined,
          recoveryCodesRemaining: typeof data.recoveryCodesRemaining === 'number' ? data.recoveryCodesRemaining : 0,
        });
        setMfaErr('');
      } else {
        setMfaErr(accountErrorFrom(res.status, data && data.error));
      }
    } catch {
      setMfaErr('error');
    }
  }, []);

  useEffect(function () { void (async function () { await loadMfa(); })(); }, [loadMfa]);

  // The same derivation the Home dashboard rings, fed from the data this view
  // already loads plus the one activity page above — identical inputs, so the two
  // rings cannot report different numbers for the same account. A section that is
  // still loading or that failed passes null, which makes its check `unknown` and
  // drops it out of the score rather than counting it against the user.
  const health = deriveHealth({
    emailVerified: user.emailVerified,
    activity: activityErr ? null : activity,
    sessionCount: sessionsLoading || sessionsErr ? null : sessions.length,
  });
  const healthLoading = activity === null && !activityErr;
  const failing = health.checks.filter(function (c) { return c.state === 'warn'; });

  const headline = healthLoading ? 'Checking your account…'
    : health.scored === 0 ? 'We couldn’t check your account'
      : health.score === 100 ? 'Your account is well protected'
        : health.score >= 50 ? 'Your account is mostly protected'
          : 'Your account needs attention';
  const headSub = healthLoading ? 'Reading your security settings.'
    : health.scored === 0 ? 'None of the security checks could run right now. Try again in a moment.'
      : failing.length === 0 ? (health.scored === 1 ? 'The one check we can run is passing.' : 'All ' + health.scored + ' checks we can run are passing.')
        : health.passing + ' of ' + health.scored + ' check' + (health.scored === 1 ? '' : 's') + ' passing — ' +
          failing.map(function (c) { return c.label.toLowerCase(); }).join(', ') + ' still ' +
          (failing.length === 1 ? 'needs' : 'need') + ' attention.';

  return (
    <div className="fade-in">
      <PageHead title="Security" sub="Protect your account with a strong password, and review where you are signed in.">
        <button type="button" className="btn ghost" onClick={endOthers} disabled={sessionBusy}><Icon name="logout" size={15} sw={2} />Sign out everywhere</button>
      </PageHead>
      <NotWiredBanner>Your security score, password change, two-step verification and active-session management are live via the self-service account API. Password age, password strength and the recovery options are still placeholder data with no self-service API yet — wire them when those surfaces land.</NotWiredBanner>

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
          </div>
        </div>
      </div>

      {/* Two-step verification — LIVE via /api/account/mfa */}
      <div className="card card-pad" style={{ marginTop: 16 }}>
        <span className="sect-title"><Icon name="shield" size={13} sw={2} />Two-step verification</span>
        <div className="lrow" style={{ paddingTop: 6, borderBottom: 'none' }}>
          <span className={'licon' + (mfa?.active ? ' good' : '')}><Icon name={mfa?.active ? 'shield' : 'shieldHalf'} size={18} sw={2} /></span>
          <div className="lmain">
            <div className="lttl">
              Authenticator app
              {mfa?.active && <span className="badge green" style={{ marginLeft: 4 }}><span className="bdot"></span>On</span>}
              {mfa && !mfa.active && <span className="badge gray" style={{ marginLeft: 4 }}>Off</span>}
            </div>
            <div className="lsub">{mfaSubtext(mfa, mfaErr)}</div>
          </div>
          <span className="lend">
            {mfa && !mfa.active && (
              <button type="button" className="btn sm" onClick={function () { setMfaModal(true); }}>Turn on</button>
            )}
          </span>
        </div>
        {mfaErr && (
          <div style={{ marginTop: 8, fontSize: 13, color: mfaErr === 'reauth' ? 'var(--error)' : 'var(--warn)' }}>
            {mfaErr === 'reauth' && <>Your session is no longer valid. <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
            {mfaErr === 'rate' && 'Too many attempts. Please wait a minute and try again.'}
            {(mfaErr === 'error' || mfaErr === 'unavailable') && 'Could not read your two-step settings. Please try again in a moment.'}
          </div>
        )}
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

      {/* Two-step enrolment modal */}
      {mfaModal && (
        <MfaEnrollModal
          onClose={function () { setMfaModal(false); }}
          onEnrolled={function () {
            setMfaModal(false);
            A.toast('Two-step verification is on', 'shield');
            void loadMfa();
          }}
        />
      )}

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
    </div>
  );
}
