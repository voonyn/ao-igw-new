// AlphaOmega User Portal — view data, ported from the Claude Design mockup
// (project 9d848fa1, portal/data.js).
//
// NOT WIRED: everything here is placeholder/illustrative. The ONLY values backed
// by a real backend today are a few `user` fields, overridden at request time
// from the OIDC /userinfo claims by `mergeUserinfo`. Every other collection
// (security, sessions, devices, apps, activity, notifications, tickets, spaces,
// ...) has no self-service API yet and is shown with a "Not Wired" marker.

import type {
  AccessRequest, AppEntitlement, DeviceRow, HelpTopic,
  MfaMethod, NotificationItem, PortalUser, SecurityData, SessionRow, Space, Ticket,
} from "./types"
import type { UserinfoClaims } from "./server/userinfo"

// Placeholder baseline. Real identity fields are merged over this from /userinfo.
export const MOCK_USER: PortalUser = {
  id: "usr_9f3c21a8",
  firstName: "Marcus",
  lastName: "Chen",
  displayName: "Marcus Chen",
  pronouns: "he/him",
  email: "marcus.chen@gmail.com",
  emailVerified: true,
  altEmail: "m.chen@northwind.co",
  altEmailVerified: true,
  phone: "+1 (415) 555 0148",
  phoneVerified: true,
  username: "marcus.chen",
  locale: "English (US)",
  timezone: "Pacific Time — Los Angeles",
  dob: "1990-04-17",
  memberSince: "March 2021",
  lastSignin: "Today, 8:42 AM",
  address: { line1: "212 Greenwich Street", line2: "Apt 14C", city: "San Francisco", state: "CA", zip: "94111", country: "United States" },
  avatarHue: 18,
}

/**
 * Merges the real OIDC /userinfo claims over the placeholder user. The overridden
 * fields (name, email, username, locale, ...) are the portal's only wired data;
 * the rest stay placeholder. Returns the baseline unchanged when claims is null.
 */
export function mergeUserinfo(claims: UserinfoClaims | null): PortalUser {
  if (!claims) return MOCK_USER
  const first = claims.given_name ?? MOCK_USER.firstName
  const last = claims.family_name ?? MOCK_USER.lastName
  const composed = [claims.given_name, claims.family_name].filter(Boolean).join(" ").trim()
  return {
    ...MOCK_USER,
    id: claims.sub ?? MOCK_USER.id,
    firstName: first,
    lastName: last,
    displayName: claims.name || composed || claims.preferred_username || claims.email || MOCK_USER.displayName,
    email: claims.email ?? MOCK_USER.email,
    // NOT defaulted to the placeholder: `email_verified` is a trust claim released
    // only with the email scope (migration 00020), and the account-health checklist
    // now scores it. An absent claim means the OP asserted nothing — reading that as
    // the fixture's `true` would put a fabricated pass on a live checklist.
    emailVerified: claims.email_verified ?? false,
    username: claims.preferred_username ?? MOCK_USER.username,
    locale: typeof claims.locale === "string" ? claims.locale : MOCK_USER.locale,
  }
}

export const spaces: Space[] = [
  { id: "personal", name: "Personal", kind: "CIAM", type: "Consumer identity", tile: "M", accent: "#EE4D2D", desc: "Your private AlphaOmega ID", primary: true },
  { id: "northwind", name: "Northwind Trading", kind: "WIAM", type: "Workforce — Employee", tile: "NT", accent: "#2563EB", desc: "marcus.chen@northwind.co · Engineering" },
  { id: "brightwater", name: "City of Brightwater", kind: "CIAM", type: "Citizen services", tile: "BW", accent: "#0F8A62", desc: "Resident ID · Verified" },
]

// The score and the checklist that used to live here are gone: both are now
// derived from live account data by lib/health.ts and shared by Home and Security
// (wire-portal-home). What remains is the password/recovery detail that still has
// no self-service API behind it.
export const security: SecurityData = {
  passwordAgeDays: 47,
  passwordStrength: "Strong",
  recoveryEmail: true,
  recoveryPhone: true,
  backupCodes: { total: 10, remaining: 8 },
  breachAlerts: true,
}

export const mfaMethods: MfaMethod[] = [
  { id: "m1", type: "passkey", name: "iPhone 15 Pro", detail: "Face ID · Apple", added: "Apr 2, 2026", primary: true, icon: "fingerprint" },
  { id: "m2", type: "authenticator", name: "Authenticator app", detail: "Time-based codes (TOTP)", added: "Jan 18, 2026", primary: false, icon: "phone" },
  { id: "m3", type: "sms", name: "SMS to ••• 0148", detail: "Text message codes", added: "Mar 9, 2025", primary: false, icon: "mail" },
  { id: "m4", type: "securitykey", name: "YubiKey 5C", detail: "Hardware security key", added: "Not enrolled", primary: false, icon: "key", empty: true },
]

export const sessions: SessionRow[] = [
  { id: "s1", device: "MacBook Pro", browser: "Chrome 128", os: "macOS 15", loc: "San Francisco, US", ip: "24.18.xx.xx", current: true, last: "Active now", icon: "laptop" },
  { id: "s2", device: "iPhone 15 Pro", browser: "AlphaOmega App", os: "iOS 18", loc: "San Francisco, US", ip: "24.18.xx.xx", current: false, last: "2 hours ago", icon: "phone" },
  { id: "s3", device: "iPad Air", browser: "Safari", os: "iPadOS 18", loc: "San Francisco, US", ip: "24.18.xx.xx", current: false, last: "Yesterday, 9:14 PM", icon: "phone" },
  { id: "s4", device: "Windows PC", browser: "Edge 128", os: "Windows 11", loc: "Austin, US", ip: "70.114.xx.xx", current: false, last: "3 days ago", flagged: true, icon: "laptop" },
]

export const devices: DeviceRow[] = [
  { id: "d1", name: "Marcus’s MacBook Pro", kind: "Laptop", os: "macOS 15.1", trusted: true, lastSeen: "Active now", loc: "San Francisco", icon: "laptop" },
  { id: "d2", name: "iPhone 15 Pro", kind: "Phone", os: "iOS 18.1", trusted: true, lastSeen: "2 hours ago", loc: "San Francisco", icon: "phone" },
  { id: "d3", name: "iPad Air", kind: "Tablet", os: "iPadOS 18.1", trusted: true, lastSeen: "Yesterday", loc: "San Francisco", icon: "phone" },
]

export const apps: AppEntitlement[] = [
  { id: "a1", name: "AlphaOmega Wallet", space: "personal", cat: "Finance", status: "active", desc: "Payments & digital cards", hue: 18, letter: "W" },
  { id: "a2", name: "CloudVault", space: "personal", cat: "Storage", status: "active", desc: "Personal file storage", hue: 200, letter: "C" },
  { id: "a3", name: "StreamOne", space: "personal", cat: "Media", status: "active", desc: "Music & video", hue: 332, letter: "S" },
  { id: "a4", name: "ShopHub Plus", space: "personal", cat: "Shopping", status: "requestable", desc: "Premium membership tier", hue: 62, letter: "S" },
  { id: "a5", name: "Workday", space: "northwind", cat: "HR", status: "active", desc: "HR & payroll", hue: 232, letter: "W" },
  { id: "a6", name: "Salesforce", space: "northwind", cat: "CRM", status: "active", desc: "Customer records", hue: 200, letter: "S" },
  { id: "a7", name: "Jira", space: "northwind", cat: "Engineering", status: "active", desc: "Issue tracking", hue: 232, letter: "J" },
  { id: "a8", name: "AWS Console", space: "northwind", cat: "Infrastructure", status: "pending", desc: "Production access — under review", hue: 38, letter: "A" },
  { id: "a9", name: "Datadog", space: "northwind", cat: "Observability", status: "requestable", desc: "Monitoring & APM", hue: 282, letter: "D" },
  { id: "a10", name: "Brightwater Permits", space: "brightwater", cat: "Government", status: "active", desc: "Building & parking permits", hue: 152, letter: "B" },
  { id: "a11", name: "City Tax Portal", space: "brightwater", cat: "Government", status: "active", desc: "Property & income tax", hue: 152, letter: "C" },
]

export const accessRequests: AccessRequest[] = [
  { id: "r1", app: "AWS Console", role: "Production — Read/Write", space: "northwind", status: "pending", submitted: "Jun 11, 2026", approver: "Dana Whitfield", step: "Manager approval" },
  { id: "r2", app: "Datadog", role: "Standard viewer", space: "northwind", status: "draft", submitted: "—", approver: "—", step: "Not submitted" },
  { id: "r3", app: "Salesforce", role: "Sales Ops", space: "northwind", status: "approved", submitted: "May 28, 2026", approver: "Dana Whitfield", step: "Granted" },
  { id: "r4", app: "ShopHub Plus", role: "Premium tier", space: "personal", status: "denied", submitted: "May 14, 2026", approver: "Auto-policy", step: "Payment required" },
]

// The activity fixture is gone: the Activity view now renders the caller's real
// audit feed (wire-portal-activity). Nothing should re-introduce placeholder rows
// into a live timeline — see lib/activity.ts for the action → row projection.

export const notifications: NotificationItem[] = [
  { id: "n1", title: "New sign-in from Austin, US", detail: "Was this you? Review your activity.", time: "3d", tone: "warn", unread: true, action: "activity" },
  { id: "n2", title: "Access request awaiting approval", detail: "AWS Console · with Dana Whitfield", time: "3d", tone: "accent", unread: true, action: "apps" },
  { id: "n3", title: "2 backup codes used", detail: "8 of 10 remaining", time: "1w", tone: "neutral", unread: false, action: "security" },
  { id: "n4", title: "Welcome to AlphaOmega ID", detail: "Your identity is now unified across 3 spaces.", time: "2w", tone: "good", unread: false, action: "home" },
]

export const tickets: Ticket[] = [
  { id: "TK-2041", subject: "Can’t receive SMS verification codes", cat: "Security", status: "open", updated: "2 hours ago", agent: "Priya R.", msgs: 3 },
  { id: "TK-1987", subject: "Request access to AWS production", cat: "Access", status: "pending", updated: "Yesterday", agent: "Dana W.", msgs: 5 },
  { id: "TK-1950", subject: "Update name on citizen profile", cat: "Profile", status: "resolved", updated: "Jun 2, 2026", agent: "Sam T.", msgs: 4 },
]

export const helpTopics: HelpTopic[] = [
  { id: "h1", icon: "lock", title: "Reset your password", desc: "Step-by-step recovery" },
  { id: "h2", icon: "shield", title: "Set up two-factor", desc: "Authenticator, SMS & keys" },
  { id: "h3", icon: "fingerprint", title: "Sign in with a passkey", desc: "Passwordless on any device" },
  { id: "h4", icon: "key", title: "Request app access", desc: "How approvals work" },
  { id: "h5", icon: "laptop", title: "Manage trusted devices", desc: "Review & remove devices" },
  { id: "h6", icon: "idcard", title: "Verify your identity", desc: "Citizen & workforce IDs" },
]

// The sign-in fixture is gone: Home's chart now buckets the caller's real
// login.succeeded / login.failed events from the activity feed (wire-portal-home).

// Aggregate mirroring the mockup's `window.AOP` so ported views can do `const d = AOP`.
export const AOP = {
  user: MOCK_USER, spaces, security, mfaMethods, sessions, devices,
  apps, accessRequests, notifications, tickets, helpTopics,
}
