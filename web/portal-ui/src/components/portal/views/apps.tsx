"use client";

import { useState, type ReactNode } from "react";

import { Icon } from "../icons";
import { PageHead, Seg, Modal, AppLogo, NotWiredBanner } from "../primitives";
import { AOP } from "@/lib/portal-data";
import type { Actions, AppEntitlement, Space } from "@/lib/types";

// AlphaOmega User Portal — My Applications & Access
export function AppsView({ A, spaceId, spaces }: { A: Actions; spaceId: string; spaces: Space[] }) {
  const d = AOP;
  const space = spaces.find(function (s) { return s.id === spaceId; }) || spaces[0];
  const [tab, setTab] = useState('apps');
  const [reqApp, setReqApp] = useState<AppEntitlement | null>(null);
  const [requests] = useState(d.accessRequests);

  const apps = d.apps.filter(function (a) { return a.space === spaceId; });
  const active = apps.filter(function (a) { return a.status === 'active'; });
  const requestable = apps.filter(function (a) { return a.status === 'requestable'; });
  const pending = apps.filter(function (a) { return a.status === 'pending'; });

  function submitReq() {
    A.toast('Access request submitted', 'send');
    setReqApp(null);
    setTab('requests');
  }

  const STATUS_BADGE = {
    pending: <span className="badge amber"><Icon name="clock" size={11} sw={2.4} />Pending</span>,
    approved: <span className="badge green"><span className="bdot"></span>Granted</span>,
    denied: <span className="badge red"><Icon name="x" size={11} sw={2.6} />Denied</span>,
    draft: <span className="badge gray">Draft</span>
  };

  return (
    <div className="fade-in">
      <PageHead title="My Applications" sub={'Apps you can access in ' + space.name + ', plus anything you can request.'}>
        <button type="button" className="btn ghost" onClick={function () { setTab('requests'); }}><Icon name="key" size={15} sw={2} />Access requests</button>
      </PageHead>
      <NotWiredBanner>Placeholder data. Application entitlements, the catalog and access requests have no self-service API yet.</NotWiredBanner>

      <div className="filter-row" style={{ marginBottom: 16 }}>
        <Seg options={[{ value: 'apps', label: 'My apps' }, { value: 'browse', label: 'Browse catalog' }, { value: 'requests', label: 'Requests' }]} value={tab} onChange={setTab} />
      </div>

      {tab === 'apps' && (
        <>
          {pending.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <span className="sect-title" style={{ marginBottom: 12 }}><Icon name="clock" size={13} sw={2} />Pending approval</span>
              <div className="app-grid">
                {pending.map(function (a) { return <AppCard key={a.id} app={a} A={A} badge={STATUS_BADGE.pending} />; })}
              </div>
            </div>
          )}
          <span className="sect-title" style={{ marginBottom: 12 }}><Icon name="check" size={13} sw={2.6} />Active access · {active.length}</span>
          <div className="app-grid stagger">
            {active.map(function (a) {
              return (
                <div key={a.id} className="app-tile" onClick={function () { A.toast('Opening ' + a.name, 'link'); }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <AppLogo letter={a.letter} hue={a.hue} />
                    <span className="badge green"><span className="bdot"></span>Active</span>
                  </div>
                  <div className="app-name">{a.name}</div>
                  <div className="app-desc">{a.desc}</div>
                  <div className="app-foot"><span className="chip">{a.cat}</span><span style={{ marginLeft: 'auto', color: 'var(--accent)', fontWeight: 600, fontSize: 12.5, display: 'flex', alignItems: 'center', gap: 4 }}>Open<Icon name="arrowR" size={13} sw={2.2} /></span></div>
                </div>
              );
            })}
          </div>
        </>
      )}

      {tab === 'browse' && (
        requestable.length > 0 ? (
          <>
            <span className="sect-title" style={{ marginBottom: 12 }}><Icon name="apps" size={13} sw={2} />Available to request</span>
            <div className="app-grid stagger">
              {requestable.map(function (a) {
                return (
                  <div key={a.id} className="app-tile">
                    <AppLogo letter={a.letter} hue={a.hue} />
                    <div className="app-name">{a.name}</div>
                    <div className="app-desc">{a.desc}</div>
                    <div className="app-foot">
                      <span className="chip">{a.cat}</span>
                      <button type="button" className="btn sm primary" style={{ marginLeft: 'auto' }} onClick={function () { setReqApp(a); }}>Request</button>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        ) : (
          <div className="card"><div className="empty"><span className="e-icon"><Icon name="check" size={26} sw={2} /></span><div className="e-ttl">You already have everything</div><div className="e-sub">There are no additional apps to request in {space.name} right now.</div></div></div>
        )
      )}

      {tab === 'requests' && (
        <div className="card card-pad" style={{ paddingTop: 8, paddingBottom: 8 }}>
          {requests.map(function (r) {
            return (
              <div key={r.id} className="lrow" style={{ cursor: 'pointer' }} onClick={function () { A.toast(r.app + ' · ' + r.step); }}>
                <span className="licon accent"><Icon name="key" size={18} sw={2} /></span>
                <div className="lmain">
                  <div className="lttl">{r.app}</div>
                  <div className="lsub">{r.role}{r.approver !== '—' ? ' · with ' + r.approver : ' · ' + r.step}{r.submitted !== '—' ? ' · ' + r.submitted : ''}</div>
                </div>
                <span className="lend">{STATUS_BADGE[r.status]}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* Request modal */}
      {reqApp && (
        <Modal onClose={function () { setReqApp(null); }} width={440}>
          <div className="drawer-head"><AppLogo letter={reqApp.letter} hue={reqApp.hue} size={32} /><span className="card-title">Request {reqApp.name}</span><span style={{ marginLeft: 'auto' }}><button type="button" className="icon-btn" onClick={function () { setReqApp(null); }}><Icon name="x" size={18} /></button></span></div>
          <div className="drawer-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div><label className="field-label">Role / access level</label><select className="text-input select-input" defaultValue="Standard"><option>Standard viewer</option><option>Editor</option><option>Administrator</option></select></div>
              <div><label className="field-label">Business justification</label><textarea className="text-input" rows={3} placeholder="Why do you need access?"></textarea></div>
              <div style={{ fontSize: 12.5, color: 'var(--muted)', display: 'flex', gap: 8, alignItems: 'flex-start' }}><Icon name="clock" size={15} sw={2} style={{ flexShrink: 0, marginTop: 1 }} />Requests are typically reviewed within 1 business day by your manager.</div>
            </div>
          </div>
          <div className="drawer-foot">
            <button type="button" className="btn ghost" style={{ flex: 1 }} onClick={function () { setReqApp(null); }}>Cancel</button>
            <button type="button" className="btn primary" style={{ flex: 1 }} onClick={submitReq}><Icon name="send" size={15} sw={2} />Submit request</button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function AppCard({ app, A, badge }: { app: AppEntitlement; A: Actions; badge: ReactNode }) {
  return (
    <div className="app-tile" onClick={function () { A.toast(app.name + ' · ' + app.desc); }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <AppLogo letter={app.letter} hue={app.hue} />
        {badge}
      </div>
      <div className="app-name">{app.name}</div>
      <div className="app-desc">{app.desc}</div>
      <div className="app-foot"><span className="chip">{app.cat}</span></div>
    </div>
  );
}
