import type { CSSProperties, ReactNode } from "react";

/* Simple line icon set ported from the AlphaOmega design handoff. */
const ICON_PATHS: Record<string, ReactNode> = {
  grid: (<g><rect x="3.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.8" /></g>),
  users: (<g><circle cx="9" cy="8" r="3.4" /><path d="M3.5 19.5c0-3 2.5-5 5.5-5s5.5 2 5.5 5" /><path d="M15.5 5.2a3.4 3.4 0 0 1 0 5.9" /><path d="M17.5 14.8c1.8.7 3 2.2 3 4.2" /></g>),
  group: (<g><circle cx="12" cy="6.5" r="3" /><circle cx="6" cy="16.5" r="3" /><circle cx="18" cy="16.5" r="3" /><path d="M9.5 9.2 7.5 13.6M14.5 9.2l2 4.4M9 16.5h6" /></g>),
  shield: (<g><path d="M12 3 20 5.8V12c0 5-3.4 8.2-8 9.7C7.4 20.2 4 17 4 12V5.8Z" /><path d="m9.2 11.8 2 2 3.8-4" /></g>),
  key: (<g><circle cx="8.5" cy="14.5" r="4.5" /><path d="m12 11 7.5-7.5M16 6.5l2.5 2.5M13.5 9l2 2" /></g>),
  scroll: (<g><path d="M7 3.5h11.5v14a3 3 0 0 1-3 3H7" /><path d="M7 3.5a2.5 2.5 0 0 0-2.5 2.5v12a2.5 2.5 0 0 0 5 0v-1h8" /><path d="M10.5 8h4.5M10.5 11.5h4.5" /></g>),
  apps: (<g><rect x="3.5" y="3.5" width="17" height="17" rx="3" /><path d="M3.5 9h17M9 9v11.5" /></g>),
  settings: (<g><circle cx="12" cy="12" r="3.2" /><path d="M12 2.8v2.4M12 18.8v2.4M21.2 12h-2.4M5.2 12H2.8M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7M18.5 18.5l-1.7-1.7M7.2 7.2 5.5 5.5" /></g>),
  search: (<g><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.4-4.4" /></g>),
  plus: <path d="M12 5v14M5 12h14" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  check: <path d="M5 12.5 10 17.5 19 6.5" />,
  chevD: <path d="m6 9 6 6 6-6" />,
  chevR: <path d="m9 6 6 6-6 6" />,
  chevUD: <path d="m7 9.5 5-5 5 5M7 14.5l5 5 5-5" />,
  dots: (<g><circle cx="5" cy="12" r="1.6" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" /><circle cx="19" cy="12" r="1.6" fill="currentColor" stroke="none" /></g>),
  help: (<g><circle cx="12" cy="12" r="9" /><path d="M9.5 9.2a2.6 2.6 0 0 1 5.1.8c0 1.7-2.6 2.2-2.6 3.6M12 16.8h.01" /></g>),
  mail: (<g><rect x="3" y="5" width="18" height="14" rx="2.5" /><path d="m3.5 7 8.5 6 8.5-6" /></g>),
  lock: (<g><rect x="4.5" y="10.5" width="15" height="10" rx="2.5" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></g>),
  phone: (<g><rect x="6.5" y="2.5" width="11" height="19" rx="2.5" /><path d="M10.5 18.5h3" /></g>),
  globe: (<g><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.4 3.8 5.5 3.8 9S14.5 18.6 12 21c-2.5-2.4-3.8-5.5-3.8-9S9.5 5.4 12 3Z" /></g>),
  clock: (<g><circle cx="12" cy="12" r="9" /><path d="M12 7v5.2l3.4 2" /></g>),
  alert: (<g><path d="M12 3.5 22 20H2Z" /><path d="M12 9.5v4.5M12 17h.01" /></g>),
  download: (<g><path d="M12 4v11M7 11l5 5 5-5" /><path d="M4.5 19.5h15" /></g>),
  logout: (<g><path d="M9 4.5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h3" /><path d="M15 8.5 19 12l-4 3.5M19 12H9.5" /></g>),
  refresh: (<g><path d="M20 6.5v5h-5" /><path d="M19.5 11.5a8 8 0 1 0-1.6 5.5" /></g>),
  filter: <path d="M4 6h16M7 12h10M10 18h4" />,
  send: <path d="m4 11 16-7-5.5 16-3-6.5L4 11Z" />,
  eye: (<g><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></g>),
  copy: (<g><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5.5 14.5h-1a1.5 1.5 0 0 1-1.5-1.5V5a2 2 0 0 1 2-2h8a1.5 1.5 0 0 1 1.5 1.5v1" /></g>),
  arrowR: <path d="M5 12h14M13 6l6 6-6 6" />,
  arrowL: <path d="M19 12H5M11 6l-6 6 6 6" />,
  arrowUp: <path d="M12 19V5M6 11l6-6 6 6" />,
  arrowDown: <path d="M12 5v14M6 13l6 6 6-6" />,
  columns: (<g><rect x="3.5" y="4.5" width="17" height="15" rx="2" /><path d="M9.5 4.5v15M14.5 4.5v15" /></g>),
  laptop: (<g><rect x="4.5" y="4.5" width="15" height="10.5" rx="2" /><path d="M2.5 19h19" /></g>),
  ban: (<g><circle cx="12" cy="12" r="9" /><path d="M5.7 5.7l12.6 12.6" /></g>),
  building: (<g><rect x="5" y="3.5" width="14" height="17" rx="1.5" /><path d="M9 7.5h2M13 7.5h2M9 11h2M13 11h2M9 14.5h2M13 14.5h2M10.5 20.5v-3h3v3" /></g>),
  folder: (<g><path d="M3.5 7.5v11A1.5 1.5 0 0 0 5 20h14a1.5 1.5 0 0 0 1.5-1.5V8.5A1.5 1.5 0 0 0 19 7h-7.2l-1.6-2.3a1.5 1.5 0 0 0-1.2-.7H5A1.5 1.5 0 0 0 3.5 5.5Z" /></g>),
  layers: (<g><path d="m12 3.5 9 4.5-9 4.5L3 8Z" /><path d="m4.8 12.1-1.8.9 9 4.5 9-4.5-1.8-.9" /><path d="m4.8 16.1-1.8.9 9 4.5 9-4.5-1.8-.9" /></g>),
  fingerprint: (<g><path d="M7 19.5c-1.2-2-1.8-4-1.8-6.5a6.8 6.8 0 0 1 13.6 0c0 1.4-.1 2.7-.4 4" /><path d="M12 10a3 3 0 0 1 3 3c0 2.6.3 4.6 1.2 6.5" /><path d="M12 13.3c0 3 .5 5.4 1.6 7.5M8.8 13a3.2 3.2 0 0 1 .2-1.2" /><path d="M8.6 16.2c.2 1.5.6 2.9 1.3 4.3" /></g>),
  sliders: (<g><path d="M4 7h10M18 7h2M4 12h4M12 12h8M4 17h13M21 17h-1" /><circle cx="16" cy="7" r="2" /><circle cx="10" cy="12" r="2" /><circle cx="19" cy="17" r="2" /></g>),
  server: (<g><rect x="3.5" y="4" width="17" height="6.5" rx="2" /><rect x="3.5" y="13.5" width="17" height="6.5" rx="2" /><path d="M7 7.2h.01M7 16.8h.01" /></g>),
  rocket: (<g><path d="M12 16c5-3.5 7-8 7-12-4 0-8.5 2-12 7l-3.5 1L8 16.5Z" /><path d="M8 16.5 7 21l4.5-1M9.5 9.5 14 14" /></g>),
  link: (<g><path d="M10 14a4 4 0 0 0 6 .5l3-3a4 4 0 0 0-5.7-5.7l-1.5 1.5" /><path d="M14 10a4 4 0 0 0-6-.5l-3 3a4 4 0 0 0 5.7 5.7l1.5-1.5" /></g>),
  terminal: (<g><rect x="3" y="4.5" width="18" height="15" rx="2.5" /><path d="m7 9.5 3 3-3 3M12.5 15.5H17" /></g>),
  idcard: (<g><rect x="3" y="5" width="18" height="14" rx="2.5" /><circle cx="8.5" cy="11" r="2" /><path d="M5.8 16c.4-1.4 1.5-2.2 2.7-2.2s2.3.8 2.7 2.2M14 9.5h4M14 13h4" /></g>),
  sun: (<g><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></g>),
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />,
};

export function Icon({
  name,
  size = 18,
  sw = 1.8,
  style,
}: {
  name: string;
  size?: number;
  sw?: number;
  style?: CSSProperties;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={sw}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={style}
      aria-hidden="true"
    >
      {ICON_PATHS[name] || null}
    </svg>
  );
}

/* Brand mark — the shield+lock from the AlphaOmega login. */
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
