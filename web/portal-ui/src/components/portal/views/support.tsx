"use client";

import { useState } from "react";
import { Icon } from "../icons";
import { PageHead, Modal, NotWiredBanner } from "../primitives";
import { useUser } from "../flow-context";
import { AOP } from "@/lib/portal-data";
import type { Actions } from "@/lib/types";

// AlphaOmega User Portal — Help & Support
export function SupportView({ A }: { A: Actions }) {
  const d = AOP;
  const u = useUser();
  const [newTicket, setNewTicket] = useState(false);
  const [q, setQ] = useState('');

  const STATUS = {
    open: <span className="badge accent"><span className="bdot"></span>Open</span>,
    pending: <span className="badge amber"><Icon name="clock" size={11} sw={2.4} />Pending</span>,
    resolved: <span className="badge green"><Icon name="check" size={11} sw={3} />Resolved</span>
  };

  return (
    <div className="fade-in">
      <PageHead title="Help & Support" sub="Search answers, manage your tickets or reach a human.">
        <button type="button" className="btn primary" onClick={function () { setNewTicket(true); }}><Icon name="plus" size={15} sw={2.4} />New ticket</button>
      </PageHead>
      <NotWiredBanner>Placeholder data. Help articles, support tickets and contact channels have no backend yet.</NotWiredBanner>

      {/* Search hero */}
      <div className="card card-pad" style={{ marginBottom: 16, background: 'linear-gradient(135deg, var(--field), var(--white))' }}>
        <div style={{ maxWidth: 560, margin: '0 auto', textAlign: 'center', padding: '8px 0' }}>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 19, fontWeight: 700, letterSpacing: '-0.01em' }}>How can we help, {u.firstName}?</div>
          <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 4 }}>Search our help center or browse common topics below.</div>
          <div className="search-box" style={{ marginTop: 16 }}>
            <Icon name="search" size={16} />
            <input className="text-input" style={{ height: 46, fontSize: 14.5 }} value={q} placeholder="Search help articles…" onChange={function (e) { setQ(e.target.value); }} />
          </div>
        </div>
      </div>

      {/* Help topics */}
      <span className="sect-title" style={{ marginBottom: 12 }}><Icon name="help" size={13} sw={2} />Common topics</span>
      <div className="app-grid stagger" style={{ marginBottom: 16 }}>
        {d.helpTopics.map(function (h) {
          return (
            <button key={h.id} type="button" className="quick" style={{ flexDirection: 'row', alignItems: 'center' }} onClick={function () { A.toast('Opening: ' + h.title, 'help'); }}>
              <span className="qicon"><Icon name={h.icon} size={19} sw={2} /></span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="qttl">{h.title}</div>
                <div className="qsub">{h.desc}</div>
              </div>
              <Icon name="arrowR" size={15} sw={2} style={{ color: 'var(--muted-2)' }} />
            </button>
          );
        })}
      </div>

      {/* Tickets */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-head">
          <div>
            <span className="card-title">Your support tickets</span>
            <div className="card-sub">{d.tickets.filter(function (t) { return t.status !== 'resolved'; }).length} open · {d.tickets.length} total</div>
          </div>
        </div>
        <div className="card-pad" style={{ paddingTop: 8, paddingBottom: 8 }}>
          {d.tickets.map(function (t) {
            const ic = { open: 'accent', pending: '', resolved: 'good' };
            return (
              <div key={t.id} className="lrow" style={{ cursor: 'pointer' }} onClick={function () { A.toast(t.id + ' · ' + t.subject); }}>
                <span className={'licon ' + ic[t.status]} style={t.status === 'pending' ? { background: 'var(--warn-soft)', color: 'var(--warn)', borderColor: 'transparent' } : undefined}><Icon name="ticket" size={18} sw={2} /></span>
                <div className="lmain">
                  <div className="lttl">{t.subject}</div>
                  <div className="lsub"><span style={{ fontFamily: 'var(--font-mono)' }}>{t.id}</span> · {t.cat} · {t.msgs} messages · {t.agent} · {t.updated}</div>
                </div>
                <span className="lend">{STATUS[t.status]}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Contact */}
      <div className="col-2b">
        <div className="card card-pad" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span className="licon accent" style={{ width: 44, height: 44 }}><Icon name="send" size={20} sw={2} /></span>
          <div style={{ flex: 1 }}><div className="lttl">Live chat</div><div className="lsub">Typical reply in under 2 minutes</div></div>
          <button type="button" className="btn ghost sm" onClick={function () { A.toast('Starting chat…', 'send'); }}>Start chat</button>
        </div>
        <div className="card card-pad" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span className="licon" style={{ width: 44, height: 44 }}><Icon name="phone" size={20} sw={2} /></span>
          <div style={{ flex: 1 }}><div className="lttl">Call us</div><div className="lsub">Mon–Fri, 8am–8pm PT</div></div>
          <button type="button" className="btn ghost sm" onClick={function () { A.toast('1-800-ALPHA-OMEGA'); }}>View number</button>
        </div>
      </div>

      {/* New ticket modal */}
      {newTicket && (
        <Modal onClose={function () { setNewTicket(false); }} width={460}>
          <div className="drawer-head"><Icon name="ticket" size={18} sw={2} style={{ color: 'var(--accent)' }} /><span className="card-title">New support ticket</span><span style={{ marginLeft: 'auto' }}><button type="button" className="icon-btn" onClick={function () { setNewTicket(false); }}><Icon name="x" size={18} /></button></span></div>
          <div className="drawer-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div><label className="field-label">Category</label><select className="text-input select-input"><option>Security</option><option>Access</option><option>Profile</option><option>Billing</option><option>Other</option></select></div>
              <div><label className="field-label">Subject</label><input className="text-input" placeholder="Brief summary" /></div>
              <div><label className="field-label">Describe your issue</label><textarea className="text-input" rows={4} placeholder="Tell us what’s happening…"></textarea></div>
            </div>
          </div>
          <div className="drawer-foot">
            <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={function () { setNewTicket(false); }}>Cancel</button>
            <button type="button" className="btn primary" style={{ flex: 1 }} onClick={function () { setNewTicket(false); A.toast('Ticket created', 'send'); }}><Icon name="send" size={15} sw={2} />Submit ticket</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
