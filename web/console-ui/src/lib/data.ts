// AlphaOmega Console — enum labels and role vocabularies.
//
// This file used to also carry a whole seeded tenant (`createInitialDb`) from the
// in-memory prototype. Every view is schema-backed now and the console's shared
// store holds no collections at all (paginate-admin-list-api), so that sample
// data had no importer and could no longer typecheck against the shrunken `Db`.
// Deleted rather than repaired: fixture rows nothing renders are just a second,
// wrong description of the schema.

export const LABELS = {
  entityState: { 1: "Active", 2: "Inactive", 3: "Removed" } as Record<number, string>,
  userState: { 1: "Active", 2: "Inactive", 3: "Deleted", 4: "Locked", 5: "Initial" } as Record<number, string>,
  appType: { 1: "OIDC", 2: "SAML", 3: "API" } as Record<number, string>,
  keyState: { 1: "Active", 2: "Inactive", 3: "Retired" } as Record<number, string>,
  keyUse: { 1: "sig", 2: "enc" } as Record<number, string>,
  privateLabeling: { 0: "Unspecified", 1: "Enforce project branding", 2: "Allow user-org branding" } as Record<number, string>,
};

export const IAM_ROLES = ["IAM_OWNER", "IAM_ADMIN", "IAM_VIEWER"];
export const ORG_ROLES = ["ORG_OWNER", "ORG_USER_MANAGER", "ORG_PROJECT_OWNER", "ORG_VIEWER"];
export const AUTHN_METHODS = ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"];
export const GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials", "implicit"];
export const RESPONSE_TYPES = ["code", "id_token", "token"];
