// AlphaOmega Console — sample data for the v1 "Meridian Dynamics" enterprise.
// Powers the preview (not-wired) views — groups, custom roles, and the app
// catalog — and nothing else. A schema-backed view importing this file is the
// defect: a fixture rendered inside a live view is indistinguishable from real
// data to the operator reading it.

import type { LegacyApp, LegacyGroup, LegacyRole, LegacyUser } from "./types";

export const LEGACY_ROLES: LegacyRole[] = [
  { id: "org-admin", name: "Org Admin", desc: "Full administrative control over the organization, including billing and security settings.", members: 4, color: "#EE4D2D", system: true, perms: { "Users & Groups": ["read", "create", "update", "delete"], "Roles & Permissions": ["read", "create", "update", "delete"], Policies: ["read", "create", "update", "delete"], "Audit Log": ["read", "export"], Billing: ["read", "update"] } },
  { id: "security-admin", name: "Security Admin", desc: "Manages authentication policies, MFA enforcement, and risk response.", members: 6, color: "#C2410C", system: true, perms: { "Users & Groups": ["read", "update"], "Roles & Permissions": ["read"], Policies: ["read", "create", "update", "delete"], "Audit Log": ["read", "export"], Billing: [] } },
  { id: "helpdesk", name: "Helpdesk", desc: "Can reset passwords, unlock accounts, and revoke sessions. No policy access.", members: 12, system: true, perms: { "Users & Groups": ["read", "update"], "Roles & Permissions": ["read"], Policies: ["read"], "Audit Log": ["read"], Billing: [] } },
  { id: "auditor", name: "Auditor", desc: "Read-only access to all configuration and the full audit trail.", members: 3, system: true, perms: { "Users & Groups": ["read"], "Roles & Permissions": ["read"], Policies: ["read"], "Audit Log": ["read", "export"], Billing: ["read"] } },
  { id: "app-owner", name: "App Owner", desc: "Manages assignments and settings for owned applications only.", members: 18, system: false, perms: { "Users & Groups": ["read"], "Roles & Permissions": [], Policies: ["read"], "Audit Log": ["read"], Billing: [] } },
  { id: "member", name: "Member", desc: "Standard end-user access. Can manage their own profile and devices.", members: 1241, system: true, perms: { "Users & Groups": [], "Roles & Permissions": [], Policies: [], "Audit Log": [], Billing: [] } },
];

export const PERM_ACTIONS = ["read", "create", "update", "delete", "export"];
export const PERM_RESOURCES = ["Users & Groups", "Roles & Permissions", "Policies", "Audit Log", "Billing"];

export const LEGACY_USERS: LegacyUser[] = [
  { id: "u1", name: "Priya Raghavan", email: "priya.raghavan@meridian.io", dept: "Security Engineering", title: "Staff Security Engineer", roles: ["org-admin", "security-admin"], status: "Active", mfa: "Enrolled", lastActive: "2 min ago", created: "Mar 12, 2024", location: "Austin, TX", sessions: 3 },
  { id: "u2", name: "Marcus Webb", email: "marcus.webb@meridian.io", dept: "IT Operations", title: "IT Operations Lead", roles: ["security-admin", "helpdesk"], status: "Active", mfa: "Enrolled", lastActive: "14 min ago", created: "Jan 8, 2023", location: "Chicago, IL", sessions: 2 },
  { id: "u3", name: "Sofia Lindqvist", email: "sofia.lindqvist@meridian.io", dept: "Compliance", title: "GRC Manager", roles: ["auditor"], status: "Active", mfa: "Enrolled", lastActive: "1 hr ago", created: "Jun 2, 2024", location: "Stockholm, SE", sessions: 1 },
  { id: "u4", name: "Devon Carter", email: "devon.carter@meridian.io", dept: "Engineering", title: "Platform Engineer", roles: ["app-owner", "member"], status: "Active", mfa: "Not enrolled", lastActive: "3 hrs ago", created: "Nov 19, 2024", location: "Remote — US", sessions: 2 },
  { id: "u5", name: "Hana Yoshida", email: "hana.yoshida@meridian.io", dept: "Engineering", title: "Senior Frontend Engineer", roles: ["member"], status: "Active", mfa: "Enrolled", lastActive: "5 hrs ago", created: "Feb 27, 2025", location: "Tokyo, JP", sessions: 1 },
  { id: "u6", name: "Tomás Herrera", email: "tomas.herrera@meridian.io", dept: "IT Operations", title: "Helpdesk Specialist", roles: ["helpdesk"], status: "Active", mfa: "Enrolled", lastActive: "Yesterday", created: "Sep 5, 2023", location: "Mexico City, MX", sessions: 1 },
  { id: "u7", name: "Aisha Okafor", email: "aisha.okafor@meridian.io", dept: "Product", title: "Product Manager", roles: ["app-owner", "member"], status: "Active", mfa: "Enrolled", lastActive: "Yesterday", created: "Apr 14, 2024", location: "London, UK", sessions: 2 },
  { id: "u8", name: "Gregor Pavlenko", email: "gregor.pavlenko@meridian.io", dept: "Finance", title: "Financial Analyst", roles: ["member"], status: "Suspended", mfa: "Not enrolled", lastActive: "12 days ago", created: "Jul 30, 2022", location: "Berlin, DE", sessions: 0 },
  { id: "u9", name: "Lena Fischer", email: "lena.fischer@meridian.io", dept: "Compliance", title: "Compliance Analyst", roles: ["auditor", "member"], status: "Active", mfa: "Enrolled", lastActive: "2 days ago", created: "Oct 3, 2024", location: "Munich, DE", sessions: 1 },
  { id: "u10", name: "Jamal Brooks", email: "jamal.brooks@meridian.io", dept: "Sales", title: "Enterprise AE", roles: ["member"], status: "Active", mfa: "Not enrolled", lastActive: "3 days ago", created: "May 21, 2025", location: "New York, NY", sessions: 1 },
  { id: "u11", name: "Camille Roux", email: "camille.roux@meridian.io", dept: "Design", title: "Design Lead", roles: ["app-owner", "member"], status: "Active", mfa: "Enrolled", lastActive: "4 days ago", created: "Aug 11, 2023", location: "Paris, FR", sessions: 1 },
  { id: "u12", name: "Ethan Caldwell", email: "ethan.caldwell@meridian.io", dept: "Engineering", title: "Backend Engineer", roles: ["member"], status: "Invited", mfa: "Pending", lastActive: "—", created: "Jun 9, 2026", location: "—", sessions: 0 },
  { id: "u13", name: "Nadia Hassan", email: "nadia.hassan@meridian.io", dept: "Security Engineering", title: "Detection Engineer", roles: ["security-admin"], status: "Active", mfa: "Enrolled", lastActive: "6 days ago", created: "Dec 1, 2023", location: "Toronto, CA", sessions: 1 },
  { id: "u14", name: "Oliver Strand", email: "oliver.strand@meridian.io", dept: "IT Operations", title: "Systems Administrator", roles: ["helpdesk", "member"], status: "Inactive", mfa: "Enrolled", lastActive: "34 days ago", created: "Mar 17, 2022", location: "Oslo, NO", sessions: 0 },
];

export const LEGACY_APPS: LegacyApp[] = [
  { id: "ap1", name: "Slack", users: 1241, tile: "#4A154B", signOn: "SAML 2.0", provisioning: true, lastSync: "12 min ago", owner: "Marcus Webb", groups: ["All Employees"], status: "Healthy" },
  { id: "ap2", name: "GitHub", users: 386, tile: "#24292F", signOn: "SAML 2.0", provisioning: true, lastSync: "26 min ago", owner: "Devon Carter", groups: ["Engineering"], status: "Healthy" },
  { id: "ap3", name: "Salesforce", users: 214, tile: "#0176D3", signOn: "SAML 2.0", provisioning: false, lastSync: "6 hrs ago", owner: "Jamal Brooks", groups: ["Sales", "Finance"], status: "Sync issue" },
  { id: "ap4", name: "Figma", users: 158, tile: "#5B3FD4", signOn: "SAML 2.0", provisioning: true, lastSync: "18 min ago", owner: "Camille Roux", groups: ["Design", "Product"], status: "Healthy" },
  { id: "ap5", name: "AWS Console", users: 92, tile: "#B45309", signOn: "SAML 2.0", provisioning: true, lastSync: "31 min ago", owner: "Priya Raghavan", groups: ["Engineering", "Security On-call"], status: "Healthy" },
  { id: "ap6", name: "Notion", users: 642, tile: "#37352F", signOn: "OIDC", provisioning: true, lastSync: "9 min ago", owner: "Aisha Okafor", groups: ["All Employees"], status: "Healthy" },
];

export const LEGACY_GROUPS: LegacyGroup[] = [
  { id: "g1", name: "All Employees", members: 1284, source: "SCIM", roles: ["member"], apps: ["Slack", "Notion"], owner: "System", synced: "38 min ago", desc: "Every active identity in the directory. Membership is managed automatically." },
  { id: "g2", name: "Engineering", members: 412, source: "SCIM", roles: ["member"], apps: ["GitHub", "Slack", "AWS Console"], owner: "Devon Carter", synced: "38 min ago", desc: "Synced from the Workday org tree — Engineering division." },
  { id: "g3", name: "Security On-call", members: 9, source: "Manual", roles: ["security-admin"], apps: ["AWS Console"], owner: "Priya Raghavan", synced: "—", desc: "Rotating incident responders. Grants break-glass access during declared incidents." },
  { id: "g4", name: "Design", members: 37, source: "SCIM", roles: ["member"], apps: ["Figma", "Slack"], owner: "Camille Roux", synced: "38 min ago", desc: "Synced from the Workday org tree — Design studio." },
  { id: "g5", name: "Finance", members: 54, source: "SCIM", roles: ["member"], apps: ["Salesforce"], owner: "Sofia Lindqvist", synced: "38 min ago", desc: "Synced from the Workday org tree — Finance division." },
  { id: "g6", name: "Helpdesk Tier 1", members: 12, source: "Manual", roles: ["helpdesk"], apps: ["Slack"], owner: "Marcus Webb", synced: "—", desc: "Front-line support staff. Maps the Helpdesk role for password resets and unlocks." },
  { id: "g7", name: "Contractors — Q3", members: 23, source: "Manual", roles: ["member"], apps: ["Slack"], owner: "Marcus Webb", synced: "—", expires: "Sep 30, 2026", desc: "Time-boxed access for Q3 contractors. Memberships auto-expire on the end date." },
];

export function createInitialLegacy() {
  return structuredClone({
    roles: LEGACY_ROLES,
    users: LEGACY_USERS,
    apps: LEGACY_APPS,
    groups: LEGACY_GROUPS,
  });
}
