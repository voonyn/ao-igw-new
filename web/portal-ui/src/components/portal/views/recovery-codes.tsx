"use client";

import { Icon } from "../icons";
import { Modal } from "../primitives";

// The one screen that shows a set of Recovery Codes.
//
// Two paths reach it: the enrolment, and the replacement. The gateway discloses
// a set exactly once, on the answer that minted it, so both paths must show the
// same warning and offer the same single exit. A second copy of this screen is
// how the two would come to say different things about the same codes.
//
// onSaved is the only way out. It runs after the person says they saved the
// codes, and the page behind then re-reads the live state.
export function RecoveryCodesModal({
  title,
  lede,
  codes,
  onSaved,
}: {
  title: string;
  lede: string;
  codes: string[];
  onSaved: () => void;
}) {
  return (
    <Modal onClose={onSaved}>
      <div className="drawer-head">
        <Icon name="key" size={18} sw={2} style={{ color: 'var(--accent)' }} />
        <span className="card-title">{title}</span>
      </div>
      <div className="drawer-body">
        <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 12, textWrap: 'pretty' }}>{lede}</p>
        <ul style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, listStyle: 'none', padding: 14, margin: 0, border: '1px solid var(--border)', borderRadius: 10, background: 'var(--field)', fontFamily: 'var(--font-mono)', fontSize: 14 }}>
          {codes.map(function (c) {
            return <li key={c} style={{ textAlign: 'center', letterSpacing: '0.06em', userSelect: 'all' }}>{c}</li>;
          })}
        </ul>
      </div>
      <div className="drawer-foot">
        <button type="button" className="btn primary" style={{ flex: 1 }} onClick={onSaved}>I’ve saved my codes</button>
      </div>
    </Modal>
  );
}
