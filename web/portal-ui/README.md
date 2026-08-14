# portal-ui — AlphaOmega User Self-Service Portal

End-user account portal for the AlphaOmega Identity Gateway. Ported from the
Claude Design mockup *"AlphaOmega User Portal"*. It is an **OIDC relying party**
that authenticates via **authorization_code + PKCE** (public client, server-side
token custody — the same BFF pattern as `console-ui`).

- Dev port: **3001** (`login-ui` = 3000, `console-ui` = 3002)
- Stack: Next.js 16 (App Router) · React 19 · TypeScript · `jose`
- Views: Home · Profile · Security · Apps · Devices · Activity · Support

## Getting started

```bash
pnpm install
cp .env.example .env.local   # then fill AO_OIDC_CLIENT_ID
pnpm dev                     # http://localhost:3001
```

### Configuration (`.env.local`)

| Var | Meaning |
| --- | --- |
| `AO_OIDC_ISSUER` | Gateway issuer; discovery + `/userinfo` + logout are found from it. |
| `AO_OIDC_CLIENT_ID` | The `portal-ui` client_id printed once by `go run . bootstrap`. |
| `AO_PORTAL_URL` | This portal's public origin (default `http://localhost:3001`). Must match the registered redirect URIs. |
| `AO_OIDC_ACCOUNT_RESOURCE` | RFC 8707 resource indicator sent at `/authorize` so the token's `aud` carries the account audience the self-service account API requires. Default `urn:alphaomega:account-api`; must match the gateway's `oidc.AccountAudience`. |

The `portal-ui` OIDC client is **already seeded by the gateway's `bootstrap`**
command (public SPA + PKCE, redirect `{AO_PORTAL_URL}/auth/callback`, post-logout
`{AO_PORTAL_URL}/`). Recover its client_id from the DB if lost:

```sql
SELECT c.client_id FROM application_oidc_configs c
  JOIN applications a ON a.id = c.app_id WHERE a.name = 'portal-ui';
```

## What's wired vs. Not Wired

The portal authenticates with the **user's own** OIDC access token. Only the OIDC
protocol endpoints are reachable with that token today — the login API is
PAT-gated + tied to a login session, and the admin API needs tenant/org
membership. So most of the rich mockup is **placeholder data**, marked in-app
with a **"Not Wired"** banner/pill.

| Feature | Backend | Status |
| --- | --- | --- |
| Login (authorization_code + PKCE) | `/authorize` + `/token` | ✅ Wired |
| Profile identity / Home greeting (name, email, username, locale, email-verified) | `/userinfo` (read-only) | ✅ Wired |
| Sign out (RP-initiated) | `/logout` (end_session) | ✅ Wired |
| Password change | `/api/v1/account/password` (self-service account API) | ✅ Wired |
| Edit profile · phone · address · preferences · data export · deactivate | — | ⛔ Not Wired |
| MFA/TOTP/passkeys · backup codes · session revocation | — | ⛔ Not Wired |
| App entitlements · catalog · access requests | — | ⛔ Not Wired |
| Trusted devices · connected apps (OAuth grants) | — | ⛔ Not Wired |
| Activity timeline · notifications | — | ⛔ Not Wired |
| Support tickets · help center | — | ⛔ Not Wired |
| Identity "spaces" switcher (multi-tenant) | — | ⛔ Not Wired |

To wire a Not-Wired area later, add a self-service Go endpoint reachable with the
user's access token, then replace the placeholder read in the matching
`src/components/portal/views/*.tsx` (data lives in `src/lib/portal-data.ts`).

## Layout

```
src/
  app/
    page.tsx              # server: gate session → fetch /userinfo → render <PortalApp>
    layout.tsx            # fonts + persisted theme
    globals.css           # design CSS (ported verbatim from the mockup)
    auth/{login,callback,logout}/route.ts   # OIDC RP: PKCE start, code exchange, RP-initiated logout
  proxy.ts                # middleware: gate all pages behind the session cookie
  lib/
    server/               # BFF: oidc-config, pkce, oidc (jose), session store/cookie, token, userinfo, redirect
    portal-data.ts        # placeholder view data + mergeUserinfo(claims)
    types.ts
  components/portal/
    shell.tsx             # PortalApp: topbar nav, notifications drawer, toasts, theme, sign-out
    icons.tsx, primitives.tsx, flow-context.tsx
    views/*.tsx           # the 7 views
```
