"use client";

import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";

import { Icon } from "./icons";

// Shared UI primitives, ported from the Claude Design mockup (portal/components.jsx),
// plus the portal-specific `NotWired` markers.

/* ---------- Avatar ---------- */
const AVATAR_HUES = [18, 152, 232, 282, 332, 62, 200];
export function Avatar({ name, size = 32, fontSize, hue }: { name: string; size?: number; fontSize?: number; hue?: number }) {
  const initials = (name || "?").split(" ").map((p) => p[0]).slice(0, 2).join("");
  let h = 0;
  for (let i = 0; i < (name || "").length; i++) h = (h * 31 + name.charCodeAt(i)) % 9973;
  const useHue = hue != null ? hue : AVATAR_HUES[h % AVATAR_HUES.length];
  return (
    <span className="avatar" style={{ width: size, height: size, fontSize: fontSize || Math.round(size * 0.38), background: "oklch(0.62 0.14 " + useHue + ")" }}>{initials}</span>
  );
}

/* ---------- Security ring ---------- */
export function SecurityRing({ score, size = 132, stroke = 11, light }: { score: number; size?: number; stroke?: number; light?: boolean }) {
  const [shown, setShown] = useState(score);
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  useEffect(() => {
    // Count up from ~0 on mount. The first setShown happens inside the rAF
    // callback (not synchronously in the effect body), and a frozen frame keeps
    // the score-initialized value rather than reading 0.
    let raf = 0;
    let start: number | null = null;
    function step(ts: number) {
      if (start === null) start = ts;
      const p = Math.min(1, (ts - start) / 900);
      const eased = 1 - Math.pow(1 - p, 3);
      setShown(Math.round(score * eased));
      if (p < 1) raf = requestAnimationFrame(step);
    }
    raf = requestAnimationFrame(step);
    const fallback = setTimeout(() => setShown(score), 700);
    return () => { cancelAnimationFrame(raf); clearTimeout(fallback); };
  }, [score]);
  const offset = circ * (1 - shown / 100);
  return (
    <div className="ring-wrap" style={{ width: size, height: size }}>
      <svg className="ring-svg" width={size} height={size} viewBox={"0 0 " + size + " " + size}>
        <circle className="ring-track" cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} />
        <circle className="ring-prog" cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke}
          strokeDasharray={circ} strokeDashoffset={offset}
          transform={"rotate(-90 " + size / 2 + " " + size / 2 + ")"} />
      </svg>
      <div className="ring-label" style={{ color: light ? "#fff" : "var(--ink)" }}>
        <div className="ring-num">{Math.round(shown)}</div>
        <div className="ring-cap">Secure</div>
      </div>
    </div>
  );
}

/* ---------- Small bits ---------- */
export function KV({ k, v }: { k: ReactNode; v: ReactNode }) {
  return <div className="kv"><span className="k">{k}</span><span className="v">{v}</span></div>;
}

export function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button type="button" className={"toggle" + (on ? " on" : "")} role="switch" aria-checked={on}
      aria-label={label} onClick={(e) => { e.stopPropagation(); onChange(!on); }}></button>
  );
}

type SegOption = string | { value: string; label: string };
export function Seg({ options, value, onChange }: { options: SegOption[]; value: string; onChange: (v: string) => void }) {
  return (
    <div className="seg" role="tablist">
      {options.map((o) => {
        const val = typeof o === "object" ? o.value : o;
        const lbl = typeof o === "object" ? o.label : o;
        return <button key={val} role="tab" className={value === val ? "on" : ""} onClick={() => onChange(val)}>{lbl}</button>;
      })}
    </div>
  );
}

export function VerifiedBadge({ on, yes, no }: { on: boolean; yes?: string; no?: string }) {
  return on
    ? <span className="badge green"><Icon name="check" size={11} sw={3} />{yes || "Verified"}</span>
    : <span className="badge amber"><Icon name="alert" size={11} sw={2.4} />{no || "Unverified"}</span>;
}

/* ---------- Menu / Modal / Drawer ---------- */
export function Menu({ onClose, children, align }: { onClose: () => void; children: ReactNode; align?: "left" | "right" }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    function onDoc(e: MouseEvent) { if (ref.current && !ref.current.contains(e.target as Node)) onClose(); }
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onKey); };
  }, [onClose]);
  const style: CSSProperties = { top: "calc(100% + 6px)" };
  if (align === "right") style.right = 0; else style.left = 0;
  return <div className="menu" ref={ref} style={style}>{children}</div>;
}

export function Modal({ onClose, children, width }: { onClose: () => void; children: ReactNode; width?: number }) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div>
      <div className="overlay" onClick={onClose}></div>
      <div className="modal" role="dialog" aria-modal="true" style={width ? { width } : undefined}>{children}</div>
    </div>
  );
}

export function Drawer({ onClose, children, width }: { onClose: () => void; children: ReactNode; width?: number }) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div>
      <div className="overlay" onClick={onClose}></div>
      <div className="drawer" role="dialog" aria-modal="true" style={width ? { width } : undefined}>{children}</div>
    </div>
  );
}

export interface ToastItem { id: number; msg: string; icon?: string }
export function ToastHost({ toasts }: { toasts: ToastItem[] }) {
  return (
    <div className="toast-wrap" aria-live="polite">
      {toasts.map((t) => (
        <div className="toast" key={t.id}>
          <span className="tick"><Icon name={t.icon || "check"} size={15} sw={2.6} /></span>
          {t.msg}
        </div>
      ))}
    </div>
  );
}

/* ---------- Page header ---------- */
export function PageHead({ title, sub, children }: { title: string; sub?: string; children?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {children && <div className="actions">{children}</div>}
    </div>
  );
}

export function AppLogo({ letter, hue, size = 44 }: { letter: string; hue: number; size?: number }) {
  return (
    <span className="app-logo" style={{ width: size, height: size, fontSize: size * 0.4, background: "oklch(0.6 0.15 " + hue + ")" }}>{letter}</span>
  );
}

/* ---------- "Not Wired" markers (portal-ui: no backend API yet) ---------- */

/** Inline pill flagging a section whose data/action has no backend API yet. */
export function NotWired({ label = "Not Wired", title }: { label?: string; title?: string }) {
  return (
    <span className="badge amber" title={title || "No backend API yet — placeholder data"}>
      <Icon name="alert" size={11} sw={2.4} />{label}
    </span>
  );
}

/** Full-width banner marking a whole view as not yet wired to the backend. */
export function NotWiredBanner({ children }: { children?: ReactNode }) {
  return (
    <div className="nw-banner" role="note">
      <Icon name="alert" size={15} sw={2} />
      <span><strong>Not Wired</strong> — {children || "this view shows placeholder data. No self-service API exists for it yet; wire it when the backend endpoint lands."}</span>
    </div>
  );
}
