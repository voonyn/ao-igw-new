import Link from "next/link"

export const metadata = {
  title: "No access — AlphaOmega Console",
}

// The portal is where a person without an administrative role belongs. An unset
// AO_PORTAL_URL renders no link, rather than a link to a guess.
const PORTAL_URL = process.env.AO_PORTAL_URL ?? ""

const COPY: Record<string, { title: string; body: string }> = {
  not_a_console_user: {
    title: "You don't have console access",
    body: "Your account signed in, but the console needs an administrator role: IAM_OWNER or IAM_ADMIN on the tenant, or ORG_OWNER or ORG_USER_MANAGER in an organization. Ask an administrator to grant you one. To manage your own account, use the portal.",
  },
  invalid_state: {
    title: "Sign-in could not be verified",
    body: "The login response didn't match this browser's pending request. Please start the sign-in again.",
  },
  exchange_failed: {
    title: "Sign-in failed",
    body: "We couldn't complete the secure token exchange with the identity gateway. Please try again.",
  },
  idtoken_invalid: {
    title: "Sign-in could not be verified",
    body: "The identity token returned by the gateway failed validation (issuer, audience, nonce, or signature). Please try again.",
  },
  me_unavailable: {
    title: "Console is unavailable",
    body: "Sign-in succeeded but the admin API could not be reached. Please try again shortly.",
  },
}

// Standalone page (outside the console layout) shown when the membership gate
// returns 403, or when the auth flow aborts. Never renders dashboard content.
export default async function NoAccessPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>
}) {
  const { error } = await searchParams
  const copy = (error && COPY[error]) || COPY.not_a_console_user
  const showPortal = PORTAL_URL !== "" && (!error || error === "not_a_console_user")

  return (
    <main
      style={{
        minHeight: "100dvh",
        display: "grid",
        placeItems: "center",
        padding: "2rem",
        background: "#0b0c0f",
        color: "#e8e9ec",
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <div style={{ maxWidth: 460, textAlign: "center" }}>
        <div style={{ fontSize: 13, letterSpacing: 2, textTransform: "uppercase", opacity: 0.5 }}>
          AlphaOmega Admin Console
        </div>
        <h1 style={{ margin: "0.75rem 0", fontSize: 26, fontWeight: 700 }}>{copy.title}</h1>
        <p style={{ margin: "0 0 1.75rem", lineHeight: 1.6, opacity: 0.75 }}>{copy.body}</p>
        <div style={{ display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
          <Link
            href="/auth/logout"
            style={{
              display: "inline-block",
              padding: "0.6rem 1.25rem",
              borderRadius: 8,
              background: "#5b6bf5",
              color: "#fff",
              fontWeight: 600,
              textDecoration: "none",
            }}
          >
            Sign in as a different user
          </Link>
          {showPortal && (
            <a
              href={PORTAL_URL}
              style={{
                display: "inline-block",
                padding: "0.6rem 1.25rem",
                borderRadius: 8,
                border: "1px solid #33353c",
                color: "#e8e9ec",
                fontWeight: 600,
                textDecoration: "none",
              }}
            >
              Go to the portal
            </a>
          )}
        </div>
      </div>
    </main>
  )
}
