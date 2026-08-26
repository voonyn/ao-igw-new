// AlphaOmega User Portal — view data, ported from the Claude Design mockup
// (project 9d848fa1, portal/data.js).
//
// NOT WIRED: everything here is placeholder/illustrative. The ONLY values backed
// by a real backend today are a few `user` fields, overridden at request time
// from the OIDC /userinfo claims by `mergeUserinfo`. Every other collection
// (security, sessions, devices, notifications, spaces, ...) has no self-service
// API yet and is shown with a "Not Wired" marker.

import type {
  DeviceRow, NotificationItem, PortalUser, SecurityData, Space,
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
  breachAlerts: true,
}

export const devices: DeviceRow[] = [
  { id: "d1", name: "Marcus’s MacBook Pro", kind: "Laptop", os: "macOS 15.1", trusted: true, lastSeen: "Active now", loc: "San Francisco", icon: "laptop" },
  { id: "d2", name: "iPhone 15 Pro", kind: "Phone", os: "iOS 18.1", trusted: true, lastSeen: "2 hours ago", loc: "San Francisco", icon: "phone" },
  { id: "d3", name: "iPad Air", kind: "Tablet", os: "iPadOS 18.1", trusted: true, lastSeen: "Yesterday", loc: "San Francisco", icon: "phone" },
]

// The activity fixture is gone: the Activity view now renders the caller's real
// audit feed (wire-portal-activity). Nothing should re-introduce placeholder rows
// into a live timeline — see lib/activity.ts for the action → row projection.

export const notifications: NotificationItem[] = [
  { id: "n1", title: "New sign-in from Austin, US", detail: "Was this you? Review your activity.", time: "3d", tone: "warn", unread: true, action: "activity" },
  { id: "n4", title: "Welcome to AlphaOmega ID", detail: "Your identity is now unified across 3 spaces.", time: "2w", tone: "good", unread: false, action: "home" },
]

// The sign-in fixture is gone: Home's chart now buckets the caller's real
// login.succeeded / login.failed events from the activity feed (wire-portal-home).

// Aggregate mirroring the mockup's `window.AOP` so ported views can do `const d = AOP`.
export const AOP = {
  user: MOCK_USER, spaces, security, devices, notifications,
}
