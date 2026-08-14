// Client-side presentation helpers shared by the views that render live gateway
// data (home, security, activity, devices). The gateway returns raw request data
// — a user agent string, an RFC3339 timestamp, a status code — because it has
// neither the viewer's locale nor their timezone, and it does not own UI copy;
// deciding how any of that reads belongs here.

// AccountErr is the state a card renders after a BFF/gateway call: "" is success,
// the rest each get their own copy. It is deliberately not a message — the wording
// differs per card ("could not load your sessions" vs "your activity"), only the
// classification is shared.
export type AccountErr = "" | "reauth" | "rate" | "unavailable" | "error"

// accountErrorFrom classifies one non-200 response. Both 401 codes mean re-auth:
// `unauthenticated` = the BFF holds no server-side token, `unauthorized` = the
// gateway rejected the one it forwarded. Retrying either resends the same token
// and 401s again, so the view offers a sign-in link instead of a generic error.
// 404 means the gateway never mounted that optional sub-feature (see mountAccount)
// — a fact to state, not a failure to report.
export function accountErrorFrom(status: number, code: unknown): AccountErr {
  if (status === 401 && (code === "unauthenticated" || code === "unauthorized")) return "reauth"
  if (status === 429) return "rate"
  if (status === 404) return "unavailable"
  return "error"
}

// The gateway has no presentational metadata for an application beyond its name,
// so an app's logo is derived from its stable client id: same app, same colour,
// every render and every device.
export function appHue(clientId: string): number {
  let h = 0
  for (let i = 0; i < clientId.length; i++) h = (h * 31 + clientId.charCodeAt(i)) % 360
  return h
}

export function appLetter(name: string): string {
  const c = name.trim().charAt(0)
  return c ? c.toUpperCase() : "?"
}

// deviceLabel derives a friendly "Browser · OS" from the raw user agent. Best
// effort — an unrecognized or empty UA falls back to a generic label.
export function deviceLabel(ua: string): string {
  if (!ua) return "Unknown device"
  const os = /Windows/i.test(ua) ? "Windows"
    : /Mac OS X|Macintosh/i.test(ua) ? "macOS"
    : /iPhone|iPad|iOS/i.test(ua) ? "iOS"
    : /Android/i.test(ua) ? "Android"
    : /Linux/i.test(ua) ? "Linux" : ""
  const br = /Edg/i.test(ua) ? "Edge"
    : /Chrome|CriOS/i.test(ua) ? "Chrome"
    : /Firefox/i.test(ua) ? "Firefox"
    : /Safari/i.test(ua) ? "Safari" : ""
  return [br, os].filter(Boolean).join(" · ") || "Browser session"
}

export function deviceIcon(ua: string): string {
  return /iPhone|Android|Mobile|iPad/i.test(ua) ? "phone" : "laptop"
}

// relTime renders an ISO timestamp as a coarse "Nm/h/d ago".
export function relTime(iso: string): string {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return ""
  const mins = Math.floor((Date.now() - t) / 60000)
  if (mins < 1) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// eventTime renders a timeline timestamp in the viewer's own locale/timezone:
// relative within the last day (matching the sessions card), an absolute date
// beyond it. Falls back to the raw value if it does not parse.
export function eventTime(iso: string): string {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const d = new Date(t)
  if (Date.now() - t < 24 * 3600 * 1000) {
    return `${relTime(iso)} · ${d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}`
  }
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
}
