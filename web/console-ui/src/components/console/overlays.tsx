"use client";

import { useEffect, useRef, useState, type CSSProperties, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import { Dialog } from "radix-ui";
import { Icon } from "./icons";
import { useSetCrumbTail } from "./page-head";
import { copyToClipboard } from "./primitives";

/* ---------- Dropdown menu ---------- */
export function Menu({
  onClose,
  children,
  align,
}: {
  onClose: () => void;
  children: ReactNode;
  align?: "left" | "right" | "up";
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const style: CSSProperties = { top: "calc(100% + 6px)" };
  if (align === "right") style.right = 0;
  else style.left = 0;
  if (align === "up") {
    style.top = "auto";
    style.bottom = "calc(100% + 6px)";
    style.left = 0;
  }
  return (
    <div className="menu" ref={ref} style={style}>
      {children}
    </div>
  );
}

/* ---------- Modal & Drawer ----------
 *
 * Both are Radix `Dialog` wearing the console's own `.modal` / `.drawer` CSS,
 * following `ConfirmHost`'s `AlertDialog` next door. Radix supplies the five
 * things the hand-rolled versions declared `aria-modal` without doing: a
 * document-level portal (these used to render inside `.content`, which scrolls
 * and clips), a focus trap, initial focus, focus restore on dismiss, and scroll
 * lock. Escape is Radix's too — hence no keydown listener here any more.
 *
 * `title` is the dialog's accessible name, required by Radix and absent before.
 * It is rendered visually hidden because every call site already draws its own
 * header; the alternative — `Dialog.Title asChild` around each one — would put
 * the requirement back on the call sites, where it was skipped in the first
 * place.
 */

function DialogShell({
  className,
  title,
  onClose,
  width,
  children,
}: {
  className: string;
  title: string;
  onClose: () => void;
  width?: number;
  children: ReactNode;
}) {
  // Focus restore is ours, not Radix's. Every call site renders
  // `{open && <Modal/>}`, so `onClose` unmounts this whole tree in one commit
  // and Radix's close transition — the thing that returns focus — never runs.
  // Capturing the opener here also covers the paths Radix would never see: a
  // call site's own Cancel button, or a close driven by state elsewhere.
  const opener = useRef<HTMLElement | null>(null);
  useEffect(() => {
    opener.current = document.activeElement as HTMLElement | null;
    return () => {
      const el = opener.current;
      // On the next frame, so this lands after the unmount commit and after the
      // browser has reset focus to <body> for the removed dialog content.
      requestAnimationFrame(() => {
        el?.focus();
        // An opener can be present and still refuse focus: `scopes`' "Add claim"
        // sits in a tab panel that is hidden by the time its modal closes, which
        // leaves it connected but unfocusable. Ask, then check — and fall back to
        // the main landmark, which the layout already makes focusable for the
        // skip link. Never leave it on <body>: that drops a keyboard operator
        // back at the top of the document.
        if (document.activeElement !== el) document.getElementById("content")?.focus();
      });
    };
  }, []);

  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        {/* `aria-describedby={undefined}` opts out of the optional description
            rather than leaving a dangling reference. */}
        <Dialog.Content className={className} style={width ? { width } : undefined} aria-describedby={undefined}>
          <Dialog.Title className="sr-only">{title}</Dialog.Title>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Modal(props: { title: string; onClose: () => void; children: ReactNode; width?: number }) {
  return <DialogShell className="modal" {...props} />;
}

export function Drawer(props: { title: string; onClose: () => void; children: ReactNode; width?: number }) {
  return <DialogShell className="drawer" {...props} />;
}

/* ---------- Full-page editor (create & update views) ---------- */
export function FullPage({
  backLabel,
  crumb,
  onBack,
  width,
  children,
}: {
  backLabel: string;
  /** Names the record (or the act of creating one) as the breadcrumb's final
   * segment. Every detail and create surface goes through this component, so
   * this is the one place that has to be told. */
  crumb?: string;
  onBack: () => void;
  width?: number;
  children: ReactNode;
}) {
  useSetCrumbTail(crumb);
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      // A Modal/Drawer layered on top owns ESC first — don't also pop the page.
      if (document.querySelector(".overlay")) return;
      onBack();
    }
    document.addEventListener("keydown", onKey);
    const c = document.querySelector(".content");
    if (c) c.scrollTop = 0;
    return () => document.removeEventListener("keydown", onKey);
  }, [onBack]);
  return (
    <div className="fade-in page-full" style={width ? { maxWidth: width } : undefined}>
      <button type="button" className="back-link" onClick={onBack}>
        <Icon name="arrowL" size={15} sw={2.2} />
        Back to {backLabel}
      </button>
      {children}
    </div>
  );
}

export function EntityHeader({
  tile,
  title,
  meta,
  actions,
}: {
  tile: ReactNode;
  title: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="entity-head">
      {tile}
      <div style={{ minWidth: 0, flex: 1 }}>
        <h1 className="entity-title">{title}</h1>
        {meta && <div className="entity-meta">{meta}</div>}
      </div>
      {actions}
    </div>
  );
}

// tabId derives the stable ids the tab and its panel point at each other with.
// `group` keeps two tab sets on one screen from colliding.
const tabId = (group: string, t: string) => `${group}-tab-${t.replace(/\W+/g, "-").toLowerCase()}`;
const panelId = (group: string, t: string) => `${group}-panel-${t.replace(/\W+/g, "-").toLowerCase()}`;

export function Tabs({
  tabs,
  value,
  onChange,
  group = "tabs",
}: {
  tabs: string[];
  value: string;
  onChange: (t: string) => void;
  group?: string;
}) {
  // Roving tabindex: the tablist is ONE tab stop and the arrows move within it,
  // per the APG. Without it, Tab walks every tab before reaching the panel — on
  // the applications detail view that is five stops to read one field.
  function onKeyDown(e: ReactKeyboardEvent<HTMLButtonElement>) {
    const i = tabs.indexOf(value);
    let next: number | null = null;
    if (e.key === "ArrowRight") next = (i + 1) % tabs.length;
    else if (e.key === "ArrowLeft") next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    if (next === null) return;
    e.preventDefault();
    onChange(tabs[next]);
    document.getElementById(tabId(group, tabs[next]))?.focus();
  }

  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t}
          type="button"
          role="tab"
          id={tabId(group, t)}
          aria-selected={value === t}
          aria-controls={panelId(group, t)}
          tabIndex={value === t ? 0 : -1}
          className={value === t ? "on" : ""}
          onKeyDown={onKeyDown}
          onClick={() => onChange(t)}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

/** The panel a `Tabs` entry controls, named back at its tab. Full roving-tabindex
 * over the tablist is `polish-console-shell`'s; this is the association without
 * which the tab announces nothing about what it opened. */
export function TabPanel({ tab, group = "tabs", children }: { tab: string; group?: string; children: ReactNode }) {
  return (
    <div role="tabpanel" id={panelId(group, tab)} aria-labelledby={tabId(group, tab)} tabIndex={0}>
      {children}
    </div>
  );
}

export function SectionCard({
  title,
  tag,
  desc,
  danger,
  children,
}: {
  title: ReactNode;
  tag?: ReactNode;
  desc?: ReactNode;
  danger?: boolean;
  children: ReactNode;
}) {
  return (
    <div className={"card sect-card" + (danger ? " danger" : "")}>
      <div className="sect-info">
        <h3>
          {title}
          {tag ? <span style={{ marginLeft: 8, display: "inline-flex", verticalAlign: "middle" }}>{tag}</span> : null}
        </h3>
        {desc && <p>{desc}</p>}
      </div>
      <div className="sect-fields">{children}</div>
    </div>
  );
}

export function ReadField({
  label,
  value,
  mono,
  secret,
  toast,
  extra,
}: {
  label?: string;
  value: string | number;
  mono?: boolean;
  secret?: boolean;
  toast?: (msg: string, icon?: string, severity?: "success" | "error" | "info") => void;
  extra?: ReactNode;
}) {
  const [show, setShow] = useState(false);
  function copy() {
    void copyToClipboard(String(value), label || "value", toast);
  }
  return (
    <div>
      {label && <span className="field-label">{label}</span>}
      <div className="read-field">
        <span className={"rf-val" + (mono || secret ? " mono" : "")}>{secret && !show ? "••••••••••••••••••••••••••••••••" : value}</span>
        {extra}
        {secret && (
          <button type="button" className="rf-btn" aria-label="Reveal" onClick={() => setShow(!show)}>
            <Icon name="eye" size={15} />
          </button>
        )}
        <button type="button" className="rf-btn" aria-label="Copy" onClick={copy}>
          <Icon name="copy" size={15} />
        </button>
      </div>
    </div>
  );
}
