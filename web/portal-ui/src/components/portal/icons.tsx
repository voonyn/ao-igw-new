import type { CSSProperties, ReactNode } from "react";

// Icon set + brand mark, ported verbatim from the Claude Design mockup
// (portal/components.jsx). Stroke-based 24x24 line icons.

const ICON_PATHS: Record<string, ReactNode> = {
  home: <g><path d="M4 11.5 12 4l8 7.5" /><path d="M5.5 10v9.5h13V10" /><path d="M10 19.5v-5h4v5" /></g>,
  grid: <g><rect x="3.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.8" /></g>,
  user: <g><circle cx="12" cy="8" r="4" /><path d="M4.5 20c0-3.6 3.2-6 7.5-6s7.5 2.4 7.5 6" /></g>,
  users: <g><circle cx="9" cy="8" r="3.4" /><path d="M3.5 19.5c0-3 2.5-5 5.5-5s5.5 2 5.5 5" /><path d="M15.5 5.2a3.4 3.4 0 0 1 0 5.9" /><path d="M17.5 14.8c1.8.7 3 2.2 3 4.2" /></g>,
  shield: <g><path d="M12 3 20 5.8V12c0 5-3.4 8.2-8 9.7C7.4 20.2 4 17 4 12V5.8Z" /><path d="m9.2 11.8 2 2 3.8-4" /></g>,
  shieldHalf: <g><path d="M12 3 20 5.8V12c0 5-3.4 8.2-8 9.7C7.4 20.2 4 17 4 12V5.8Z" /></g>,
  key: <g><circle cx="8.5" cy="14.5" r="4.5" /><path d="m12 11 7.5-7.5M16 6.5l2.5 2.5M13.5 9l2 2" /></g>,
  apps: <g><rect x="3.5" y="3.5" width="17" height="17" rx="3" /><path d="M3.5 9h17M9 9v11.5" /></g>,
  settings: <g><circle cx="12" cy="12" r="3.2" /><path d="M12 2.8v2.4M12 18.8v2.4M21.2 12h-2.4M5.2 12H2.8M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7M18.5 18.5l-1.7-1.7M7.2 7.2 5.5 5.5" /></g>,
  search: <g><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.4-4.4" /></g>,
  plus: <path d="M12 5v14M5 12h14" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  check: <path d="M5 12.5 10 17.5 19 6.5" />,
  chevD: <path d="m6 9 6 6 6-6" />,
  chevR: <path d="m9 6 6 6-6 6" />,
  chevL: <path d="m15 6-6 6 6 6" />,
  chevUD: <path d="m7 9.5 5-5 5 5M7 14.5l5 5 5-5" />,
  dots: <g><circle cx="5" cy="12" r="1.6" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" /><circle cx="19" cy="12" r="1.6" fill="currentColor" stroke="none" /></g>,
  bell: <g><path d="M18 9a6 6 0 1 0-12 0c0 5-2 6-2 6h16s-2-1-2-6" /><path d="M10 18.5a2.2 2.2 0 0 0 4 0" /></g>,
  help: <g><circle cx="12" cy="12" r="9" /><path d="M9.5 9.2a2.6 2.6 0 0 1 5.1.8c0 1.7-2.6 2.2-2.6 3.6M12 16.8h.01" /></g>,
  mail: <g><rect x="3" y="5" width="18" height="14" rx="2.5" /><path d="m3.5 7 8.5 6 8.5-6" /></g>,
  lock: <g><rect x="4.5" y="10.5" width="15" height="10" rx="2.5" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></g>,
  phone: <g><rect x="6.5" y="2.5" width="11" height="19" rx="2.5" /><path d="M10.5 18.5h3" /></g>,
  globe: <g><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.4 3.8 5.5 3.8 9S14.5 18.6 12 21c-2.5-2.4-3.8-5.5-3.8-9S9.5 5.4 12 3Z" /></g>,
  clock: <g><circle cx="12" cy="12" r="9" /><path d="M12 7v5.2l3.4 2" /></g>,
  alert: <g><path d="M12 3.5 22 20H2Z" /><path d="M12 9.5v4.5M12 17h.01" /></g>,
  download: <g><path d="M12 4v11M7 11l5 5 5-5" /><path d="M4.5 19.5h15" /></g>,
  logout: <g><path d="M9 4.5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h3" /><path d="M15 8.5 19 12l-4 3.5M19 12H9.5" /></g>,
  refresh: <g><path d="M20 6.5v5h-5" /><path d="M19.5 11.5a8 8 0 1 0-1.6 5.5" /></g>,
  send: <path d="m4 11 16-7-5.5 16-3-6.5L4 11Z" />,
  eye: <g><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></g>,
  copy: <g><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5.5 14.5h-1a1.5 1.5 0 0 1-1.5-1.5V5a2 2 0 0 1 2-2h8a1.5 1.5 0 0 1 1.5 1.5v1" /></g>,
  arrowR: <path d="M5 12h14M13 6l6 6-6 6" />,
  laptop: <g><rect x="4.5" y="4.5" width="15" height="10.5" rx="2" /><path d="M2.5 19h19" /></g>,
  ban: <g><circle cx="12" cy="12" r="9" /><path d="M5.7 5.7l12.6 12.6" /></g>,
  link: <g><path d="M10 14a4 4 0 0 0 6 .5l3-3a4 4 0 0 0-5.7-5.7l-1.5 1.5" /><path d="M14 10a4 4 0 0 0-6-.5l-3 3a4 4 0 0 0 5.7 5.7l1.5-1.5" /></g>,
  fingerprint: <g><path d="M7 19.5c-1.2-2-1.8-4-1.8-6.5a6.8 6.8 0 0 1 13.6 0c0 1.4-.1 2.7-.4 4" /><path d="M12 10a3 3 0 0 1 3 3c0 2.6.3 4.6 1.2 6.5" /><path d="M12 13.3c0 3 .5 5.4 1.6 7.5M8.8 13a3.2 3.2 0 0 1 .2-1.2" /><path d="M8.6 16.2c.2 1.5.6 2.9 1.3 4.3" /></g>,
  idcard: <g><rect x="3" y="5" width="18" height="14" rx="2.5" /><circle cx="8.5" cy="11" r="2" /><path d="M5.8 16c.4-1.4 1.5-2.2 2.7-2.2s2.3.8 2.7 2.2M14 9.5h4M14 13h4" /></g>,
  ticket: <g><path d="M4 8a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2 2 2 0 0 0 0 4 2 2 0 0 1-2 2H6a2 2 0 0 1-2-2 2 2 0 0 0 0-4Z" /><path d="M13 6v2M13 11v2M13 16v2" /></g>,
  star: <path d="m12 3.5 2.6 5.4 5.9.8-4.3 4.1 1 5.9-5.2-2.8-5.2 2.8 1-5.9L3.5 9.7l5.9-.8Z" />,
  edit: <g><path d="M4 20h4L18.5 9.5a2 2 0 0 0-2.8-2.8L5 17.5Z" /><path d="m14 8 2.8 2.8" /></g>,
  trash: <g><path d="M4.5 7h15M9 7V5a1.5 1.5 0 0 1 1.5-1.5h3A1.5 1.5 0 0 1 15 5v2M6 7l1 12.5a1.5 1.5 0 0 0 1.5 1.4h7a1.5 1.5 0 0 0 1.5-1.4L18 7" /></g>,
  verified: <g><path d="m9 12 2 2 4-4" /><path d="M12 3l2.3 1.6 2.8-.2.9 2.6 2.4 1.4-.8 2.7.8 2.7-2.4 1.4-.9 2.6-2.8-.2L12 21l-2.3-1.6-2.8.2-.9-2.6L3.6 15.6l.8-2.7-.8-2.7 2.4-1.4.9-2.6 2.8.2Z" /></g>,
  sparkle: <g><path d="M12 3v4M12 17v4M3 12h4M17 12h4" /><path d="m6.5 6.5 2.5 2.5M15 15l2.5 2.5M17.5 6.5 15 9M9 15l-2.5 2.5" /></g>,
  device: <g><rect x="6.5" y="2.5" width="11" height="19" rx="2.5" /><path d="M10.5 18.5h3" /></g>,
};

export function Icon({ name, size = 18, sw = 1.8, style, className }: {
  name: string;
  size?: number;
  sw?: number;
  style?: CSSProperties;
  className?: string;
}) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" style={style} className={className} aria-hidden="true">
      {ICON_PATHS[name] ?? null}
    </svg>
  );
}

export function BrandMark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 34 34" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M17 2.5 L29 6.5 V16 C29 24 23.6 29.2 17 31.5 C10.4 29.2 5 24 5 16 V6.5 Z" fill="var(--accent, #EE4D2D)" />
      <path d="M17 2.5 L29 6.5 V16 C29 24 23.6 29.2 17 31.5 C10.4 29.2 5 24 5 16 V6.5 Z" fill="#FFFFFF" opacity="0.14" />
      <rect x="11.5" y="15.5" width="11" height="9" rx="2" fill="#fff" />
      <path d="M13.6 15.5 V13 a3.4 3.4 0 0 1 6.8 0 V15.5" stroke="#fff" strokeWidth="1.8" fill="none" strokeLinecap="round" />
      <circle cx="17" cy="19.4" r="1.5" fill="var(--accent, #EE4D2D)" />
      <rect x="16.3" y="19.8" width="1.4" height="3" rx="0.7" fill="var(--accent, #EE4D2D)" />
    </svg>
  );
}
