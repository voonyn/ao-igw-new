// Action → presentation for the Activity timeline.
//
// The gateway returns the raw dotted audit action (`login.succeeded`,
// `mfa.enrolled`, …) and nothing else: UI copy, icons and i18n do not belong in
// an IdP, and the action vocabulary is already a stable published contract
// (internal/audit/service.go). This table is the client half of that contract.
//
// An action with no entry here degrades to a neutral row showing the raw action,
// so a newly-added backend action renders as a plain line instead of vanishing.

import { deviceLabel, eventTime } from "./format"
import type { ActivityEvent, ActivityEventWire } from "./types"

// `type` feeds the view's All / Security / Account segment filter, so the values
// must stay in the buckets activity.tsx knows: security = signin | newdevice |
// mfa | password, account = profile | access | consent.
type Presentation = { type: string; icon: string; tone: ActivityEvent["tone"]; title: string }

const ACTION_PRESENTATION: Record<string, Presentation> = {
  "login.succeeded": { type: "signin", icon: "fingerprint", tone: "neutral", title: "Signed in" },
  "login.failed": { type: "signin", icon: "alert", tone: "warn", title: "Failed sign-in attempt" },
  logout: { type: "signin", icon: "logout", tone: "neutral", title: "Signed out" },
  "password.changed": { type: "password", icon: "lock", tone: "good", title: "Password changed" },
  "session.revoked": { type: "signin", icon: "logout", tone: "good", title: "Session signed out" },
  "mfa.enrolled": { type: "mfa", icon: "shield", tone: "good", title: "Two-factor method added" },
  "mfa.removed": { type: "mfa", icon: "shield", tone: "warn", title: "Two-factor method removed" },
  // Toned `warn`, not `good`: spending a recovery code means the authenticator was
  // unavailable, which is the row a user should notice if it wasn't them.
  "mfa.recovery_code_used": { type: "mfa", icon: "key", tone: "warn", title: "Recovery code used" },
  "mfa.recovery_codes_regenerated": { type: "mfa", icon: "key", tone: "good", title: "Recovery codes replaced" },
  "mfa.passkey_registered": { type: "mfa", icon: "shield", tone: "good", title: "Passkey added" },
  "consent.granted": { type: "consent", icon: "link", tone: "neutral", title: "App connected" },
  "consent.revoked": { type: "consent", icon: "link", tone: "good", title: "Revoked app access" },
  "user.updated": { type: "profile", icon: "idcard", tone: "neutral", title: "Profile updated" },
}

const FALLBACK: Omit<Presentation, "title"> = { type: "other", icon: "clock", tone: "neutral" }

// presentActivity projects one wire event onto the timeline row the view renders.
// The detail line is composed from the caller's own recorded request data (device
// from the user agent, plus the IP), and the timestamp is formatted client-side —
// the server has neither the viewer's locale nor their timezone.
//
// A recorded failure is always toned `warn` regardless of the action's own tone,
// so "password change failed" reads as something to review rather than as a
// successful change. The "— failed" suffix is added only where it disambiguates:
// an action already toned `warn` (login.failed) says so in its own title.
export function presentActivity(e: ActivityEventWire): ActivityEvent {
  const known = ACTION_PRESENTATION[e.action]
  const p = known ?? { ...FALLBACK, title: e.action }
  const failed = e.result === "failure"
  const detail = [e.userAgent ? deviceLabel(e.userAgent) : "", e.ip].filter(Boolean).join(" · ")
  return {
    id: e.id,
    type: p.type,
    icon: failed ? "alert" : p.icon,
    title: failed && known && known.tone !== "warn" ? `${p.title} — failed` : p.title,
    detail: detail || "No device details recorded",
    time: eventTime(e.createdAt),
    tone: failed ? "warn" : p.tone,
  }
}
