// Shared types for the portal's view data. Mirrors the shape of the Claude
// Design mockup's `window.AOP`. Only a handful of `user` fields are backed by a
// real API (OIDC /userinfo — see mergeUserinfo); everything else is placeholder
// data rendered with a "Not Wired" marker until a self-service API exists.

export interface Address {
  line1: string
  line2: string
  city: string
  state: string
  zip: string
  country: string
}

export interface PortalUser {
  id: string
  firstName: string
  lastName: string
  displayName: string
  pronouns: string
  email: string
  emailVerified: boolean
  altEmail: string
  altEmailVerified: boolean
  phone: string
  phoneVerified: boolean
  username: string
  locale: string
  timezone: string
  dob: string
  memberSince: string
  lastSignin: string
  address: Address
  avatarHue: number
}

export interface Space {
  id: string
  name: string
  kind: "CIAM" | "WIAM"
  type: string
  tile: string
  accent: string
  desc: string
  primary?: boolean
}

// What is left of the security fixture. The score and the checklist moved to
// AccountHealth below, derived from live data rather than declared here.
export interface SecurityData {
  passwordAgeDays: number
  passwordStrength: string
  recoveryEmail: boolean
  recoveryPhone: boolean
  backupCodes: { total: number; remaining: number }
  breachAlerts: boolean
}

export interface MfaMethod {
  id: string
  type: string
  name: string
  detail: string
  added: string
  primary: boolean
  icon: string
  empty?: boolean
}

// Passkey mirrors the gateway dto.AccountPasskey returned by the BFF
// (/api/account/passkeys). Metadata only — the credential id (base64url, used to
// delete it), an optional label, and ISO timestamps. lastUsedAt is "" until first use.
export interface Passkey {
  id: string
  name: string
  createdAt: string
  lastUsedAt: string
}

// TOTP wire types mirror the gateway account DTOs returned by the BFF
// (/api/account/totp*). Status is a boolean only; begin discloses the secret + the
// otpauth:// provisioning URI (the client renders the QR); finish returns the
// one-time recovery codes. The `code` request bodies carry only a string, so no
// separate request type is defined here.
export interface TotpStatus {
  enabled: boolean
  // How many recovery codes remain unused — a count, never the codes. Drives the
  // portal's prompt to replace them before the last one is spent.
  recoveryCodesRemaining: number
}

export interface TotpEnrollBegin {
  secret: string
  otpauthUri: string
}

export interface TotpEnrollFinish {
  recoveryCodes: string[]
}

export interface SessionRow {
  id: string
  device: string
  browser: string
  os: string
  loc: string
  ip: string
  current: boolean
  last: string
  flagged?: boolean
  icon: string
}

export interface DeviceRow {
  id: string
  name: string
  kind: string
  os: string
  trusted: boolean
  lastSeen: string
  loc: string
  icon: string
}

// ConnectedAppWire mirrors one connected app as the gateway returns it from
// /api/v1/account/connected-apps (dto.AccountConnectedApp). `name` already falls
// back to the client id server-side when the application record is gone. `active`
// means the app holds a live, unexpired grant right now — presentation only: an
// inactive app is still connected and is revoked the same way. The logo initial
// and hue are derived client-side from the client id; the gateway has no
// presentational metadata for an application beyond its name.
export interface ConnectedAppWire {
  clientId: string
  name: string
  scopes: string[]
  active: boolean
  connectedAt: string
  updatedAt: string
}

export interface AppEntitlement {
  id: string
  name: string
  space: string
  cat: string
  status: "active" | "requestable" | "pending"
  desc: string
  hue: number
  letter: string
}

export interface AccessRequest {
  id: string
  app: string
  role: string
  space: string
  status: "pending" | "draft" | "approved" | "denied"
  submitted: string
  approver: string
  step: string
}

// ActivityEvent is the *rendered* timeline row the view draws. Live events are
// projected onto this shape by presentActivity (lib/activity.ts); the remaining
// placeholder fixtures still declare it directly.
export interface ActivityEvent {
  id: string
  type: string
  icon: string
  title: string
  detail: string
  time: string
  tone: "neutral" | "warn" | "good"
}

// ActivityEventWire mirrors one event as the gateway returns it from
// /api/v1/account/activity (audit.AuditEventView with the operator-facing `actor`
// and `metadata` withheld — they are absent from the wire, not empty). `action`
// is the raw dotted audit string; mapping it to a title/icon/tone is the client's
// job (see lib/activity.ts), so presentation and localisation stay out of the
// gateway. Optional fields are omitempty server-side.
export interface ActivityEventWire {
  id: string
  action: string
  entityType: string
  entityId?: string
  result: string
  ip?: string
  userAgent?: string
  createdAt: string
}

// ActivityPage is one keyset page of the feed. nextCursor is absent once the feed
// is exhausted; it is opaque and must be echoed back verbatim to page further.
export interface ActivityPage {
  events: ActivityEventWire[]
  nextCursor?: string
}

// HealthCheck is one row of the derived account-health checklist (lib/health.ts).
// `state` is three-valued on purpose: a check whose endpoint failed or whose
// optional sub-feature the gateway never mounted is `unknown` — neither passing
// nor failing — and is excluded from the score entirely. `nav` is the portal view
// that resolves the check, so a failing row can link straight to its fix.
export interface HealthCheck {
  id: string
  label: string
  detail: string
  state: "good" | "warn" | "unknown"
  nav: string
}

// AccountHealth is what deriveHealth returns: the scored checklist, the score it
// implies, and the counts behind it. `passing`/`scored` are exposed rather than
// re-derived per view so the checklist's "N of M passing" cannot disagree with the
// ring beside it. `sessions` is informational and never scored — "how many
// sessions is too many" is not derivable, and inventing a threshold would be
// fixture data wearing a live coat.
export interface AccountHealth {
  checks: HealthCheck[]
  score: number
  passing: number
  scored: number
  sessions: { count: number; known: boolean }
}

export interface NotificationItem {
  id: string
  title: string
  detail: string
  time: string
  tone: "warn" | "accent" | "good" | "neutral"
  unread: boolean
  action: string
}

export interface Ticket {
  id: string
  subject: string
  cat: string
  status: "open" | "pending" | "resolved"
  updated: string
  agent: string
  msgs: number
}

export interface HelpTopic {
  id: string
  icon: string
  title: string
  desc: string
}

// The action bundle threaded through views (mirrors the design's `A`).
export interface Actions {
  toast: (msg: string, icon?: string) => void
  nav: (page: string) => void
}
