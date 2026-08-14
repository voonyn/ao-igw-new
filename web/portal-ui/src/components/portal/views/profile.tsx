"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Icon } from "../icons";
import { PageHead, Avatar, KV, Toggle, VerifiedBadge, NotWiredBanner } from "../primitives";
import { useUser } from "../flow-context";
import type { Actions, Space } from "@/lib/types";

// My Profile, ported from portal/views-profile.jsx.
// WIRED: identity fields (name, display name, language) read from OIDC /userinfo
// and edited via the self-service account API (/api/account/profile BFF route).
// NOT WIRED: contact numbers, mailing address, preferences, data export and
// deactivation — placeholder, flagged with the banner below.
export function ProfileView({ A, spaceId, spaces }: { A: Actions; spaceId: string; spaces: Space[] }) {
  const u = useUser();
  const router = useRouter();
  const space = spaces.find(function (s) { return s.id === spaceId; }) || spaces[0];
  const [editing, setEditing] = useState(false);
  // Identity form — the four fields the account API owns. Seeded from /userinfo
  // (via useUser) each time edit opens so the form reflects the latest saved
  // values after a router.refresh(). Contact/address/DOB inputs stay prototype.
  const [firstName, setFirstName] = useState(u.firstName);
  const [lastName, setLastName] = useState(u.lastName);
  const [displayName, setDisplayName] = useState(u.displayName);
  const [locale, setLocale] = useState(u.locale);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [reauth, setReauth] = useState(false);
  const completeness = 86;

  function startEdit() {
    setFirstName(u.firstName); setLastName(u.lastName);
    setDisplayName(u.displayName); setLocale(u.locale);
    setError(''); setReauth(false); setEditing(true);
  }
  function cancel() { setEditing(false); setError(''); setReauth(false); }

  async function save() {
    setError(''); setReauth(false); setSaving(true);
    try {
      const res = await fetch('/api/account/profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firstName, lastName, displayName, locale }),
      });
      if (res.status === 200) {
        setEditing(false);
        // Re-run the server component (fetchUserinfo) so the header card and
        // read view re-render with the persisted values — single source of truth.
        router.refresh();
        A.toast('Profile updated');
        return;
      }
      const data = await res.json().catch(function () { return {}; });
      // Gateway error codes (internal/api/http/response/api_error.go); the BFF
      // adds "unauthenticated" when no server-side token is available.
      const code = data && data.error;
      if (res.status === 401 && (code === 'unauthenticated' || code === 'unauthorized')) {
        // Both codes mean re-auth: retrying resends the same token and 401s
        // again, so offer a sign-in link instead of a generic error.
        setError('Your session is no longer valid.');
        setReauth(true);
      } else if (res.status === 400 && code === 'invalid_request') {
        setError('Please check your entries and try again.');
      } else if (res.status === 429) {
        // Limiter tripped — advise waiting; the form stays usable for a retry.
        setError('Too many attempts. Please wait a minute and try again.');
      } else if (res.status >= 500) {
        setError('The server is temporarily unavailable. Please try again in a moment.');
      } else {
        setError('Something went wrong. Please try again.');
      }
    } catch {
      setError('Something went wrong. Please try again.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fade-in">
      <PageHead title="My Profile" sub="Your personal information, contact details and preferences.">
        {editing
          ? <>
              <button type="button" className="btn ghost" onClick={cancel} disabled={saving}>Cancel</button>
              <button type="button" className="btn primary" onClick={save} disabled={saving}><Icon name="check" size={15} sw={2.4} />{saving ? 'Saving…' : 'Save changes'}</button>
            </>
          : <button type="button" className="btn ghost" onClick={startEdit}><Icon name="edit" size={15} sw={2} />Edit</button>}
      </PageHead>

      <NotWiredBanner>Your name, display name and language are editable and saved to your account via the self-service account API. Contact numbers, mailing address, preferences, data export and deactivation are still placeholders — no self-service API backs them yet.</NotWiredBanner>

      {editing && error && (
        <div style={{ marginBottom: 12, fontSize: 13, color: 'var(--error)' }}>
          {error}
          {reauth && <> <a href="/auth/login" style={{ color: 'var(--accent)', fontWeight: 600 }}>Sign in again</a></>}
        </div>
      )}

      {/* Header card */}
      <div className="card card-pad" style={{ marginBottom: 16 }}>
        <div className="profile-hd">
          <div className="ph-avatar">
            <Avatar name={u.displayName} size={72} fontSize={26} hue={u.avatarHue} />
            <span className="ph-cam" onClick={function () { A.toast('Photo upload — prototype'); }}><Icon name="edit" size={12} sw={2.2} /></span>
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="ph-name">{u.displayName}</div>
            <div className="ph-meta">{u.email} · {u.pronouns}</div>
            <div style={{ display: 'flex', gap: 7, marginTop: 9, flexWrap: 'wrap' }}>
              <span className="badge green"><Icon name="verified" size={12} sw={2} />Email verified</span>
              <span className="badge green"><Icon name="verified" size={12} sw={2} />Phone verified</span>
              <span className="badge accent">{space.kind} identity</span>
            </div>
          </div>
        </div>
        <div style={{ marginTop: 20, paddingTop: 18, borderTop: '1px solid var(--border-soft)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>Profile completeness</span>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>{completeness}%</span>
          </div>
          <div className="meter"><div className="fill" style={{ width: completeness + '%' }}></div></div>
          <div style={{ fontSize: 12.5, color: 'var(--muted)', marginTop: 8 }}>Add a recovery address to reach 100% and unlock faster account recovery.</div>
        </div>
      </div>

      <div className="col-2b">
        {/* Personal info */}
        <div className="card card-pad">
          <span className="sect-title"><Icon name="user" size={13} sw={2} />Personal information</span>
          {editing ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 6 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <div><label className="field-label">First name</label><input className="text-input" value={firstName} onChange={function (e) { setFirstName(e.target.value); }} /></div>
                <div><label className="field-label">Last name</label><input className="text-input" value={lastName} onChange={function (e) { setLastName(e.target.value); }} /></div>
              </div>
              <div><label className="field-label">Display name</label><input className="text-input" value={displayName} onChange={function (e) { setDisplayName(e.target.value); }} /></div>
              <div><label className="field-label">Pronouns</label><input className="text-input" defaultValue={u.pronouns} /></div>
              <div><label className="field-label">Date of birth</label><input className="text-input" type="date" defaultValue={u.dob} /></div>
            </div>
          ) : (
            <div style={{ marginTop: 4 }}>
              <KV k="First name" v={u.firstName} />
              <KV k="Last name" v={u.lastName} />
              <KV k="Pronouns" v={u.pronouns} />
              <KV k="Date of birth" v="April 17, 1990" />
              <KV k="Username" v={<span style={{ fontFamily: 'var(--font-mono)', fontSize: 12.5 }}>{u.username}</span>} />
            </div>
          )}
        </div>

        {/* Contact */}
        <div className="card card-pad">
          <span className="sect-title"><Icon name="mail" size={13} sw={2} />Contact details</span>
          <div style={{ marginTop: 4 }}>
            <div className="kv"><span className="k">Primary email</span><span className="v" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>{u.email}<VerifiedBadge on={u.emailVerified} /></span></div>
            <div className="kv"><span className="k">Work email</span><span className="v" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>{u.altEmail}<VerifiedBadge on={u.altEmailVerified} /></span></div>
            <div className="kv"><span className="k">Phone</span><span className="v" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>{u.phone}<VerifiedBadge on={u.phoneVerified} /></span></div>
          </div>
          {!editing && <button type="button" className="btn ghost sm" style={{ marginTop: 14 }} onClick={function () { A.toast('Add email — prototype'); }}><Icon name="plus" size={14} sw={2.4} />Add email</button>}
        </div>

        {/* Address */}
        <div className="card card-pad">
          <span className="sect-title"><Icon name="home" size={13} sw={2} />Mailing address</span>
          {editing ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 6 }}>
              <div><label className="field-label">Street address</label><input className="text-input" defaultValue={u.address.line1} /></div>
              <div><label className="field-label">Apartment, suite</label><input className="text-input" defaultValue={u.address.line2} /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 14 }}>
                <div><label className="field-label">City</label><input className="text-input" defaultValue={u.address.city} /></div>
                <div><label className="field-label">State</label><input className="text-input" defaultValue={u.address.state} /></div>
              </div>
            </div>
          ) : (
            <div style={{ marginTop: 4 }}>
              <KV k="Street" v={u.address.line1} />
              <KV k="Unit" v={u.address.line2} />
              <KV k="City" v={u.address.city} />
              <KV k="State / ZIP" v={u.address.state + ' ' + u.address.zip} />
              <KV k="Country" v={u.address.country} />
            </div>
          )}
        </div>

        {/* Preferences */}
        <div className="card card-pad">
          <span className="sect-title"><Icon name="settings" size={13} sw={2} />Preferences</span>
          <div style={{ marginTop: editing ? 6 : 4 }}>
            {editing
              ? <div style={{ marginBottom: 10 }}><label className="field-label">Language</label><input className="text-input" value={locale} onChange={function (e) { setLocale(e.target.value); }} /></div>
              : <KV k="Language" v={u.locale} />}
            <KV k="Time zone" v={u.timezone} />
          </div>
          <div style={{ marginTop: 8 }}>
            <PrefToggle label="Email notifications" sub="Security alerts & updates" defaultOn={true} A={A} />
            <PrefToggle label="Marketing emails" sub="Product news & tips" defaultOn={false} A={A} />
            <PrefToggle label="Use my data to personalize" sub="Tailored recommendations" defaultOn={true} A={A} />
          </div>
        </div>
      </div>

      {/* Danger zone */}
      <div className="card card-pad" style={{ marginTop: 16, borderColor: 'color-mix(in srgb, var(--error) 22%, var(--border))' }}>
        <span className="sect-title" style={{ color: 'var(--error)' }}><Icon name="alert" size={13} sw={2} />Account actions</span>
        <div style={{ display: 'flex', gap: 10, marginTop: 8, flexWrap: 'wrap' }}>
          <button type="button" className="btn ghost" onClick={function () { A.toast('Data export requested', 'download'); }}><Icon name="download" size={15} sw={2} />Download my data</button>
          <button type="button" className="btn danger-ghost" onClick={function () { A.toast('Deactivation — prototype', 'alert'); }}><Icon name="ban" size={15} sw={2} />Deactivate account</button>
        </div>
      </div>
    </div>
  );
}

function PrefToggle({ label, sub, defaultOn, A }: { label: string; sub: string; defaultOn: boolean; A: Actions }) {
  const [on, setOn] = useState(defaultOn);
  return (
    <div className="lrow" style={{ padding: '11px 0' }}>
      <div className="lmain">
        <div className="lttl">{label}</div>
        <div className="lsub">{sub}</div>
      </div>
      <span className="lend"><Toggle on={on} onChange={function (v) { setOn(v); A.toast(label + (v ? ' on' : ' off')); }} label={label} /></span>
    </div>
  );
}
