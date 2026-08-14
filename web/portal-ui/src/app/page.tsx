import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { PortalApp } from "@/components/portal/shell";
import { mergeUserinfo } from "@/lib/portal-data";
import { openSession, PORTAL_SESSION_COOKIE } from "@/lib/server/secure-cookie";
import { fetchUserinfo } from "@/lib/server/userinfo";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// The portal is a single-page client shell; this server component gates the
// session and resolves the authenticated user's identity from OIDC /userinfo
// (the one wired self-service read), then hands it to the client app. The
// middleware (proxy.ts) already redirects sessionless requests to /auth/login;
// this re-checks defensively and covers a dead server-side session reference.
export default async function Page() {
  const jar = await cookies();
  const session = await openSession(jar.get(PORTAL_SESSION_COOKIE)?.value);
  // No decryptable session → sign in. Middleware normally catches this first;
  // this is the defensive re-check.
  if (!session) redirect("/auth/login");

  // Middleware keeps the token fresh; a transient /userinfo miss degrades the
  // profile to placeholders rather than bouncing to login (which would loop if
  // it recurred). A truly dead session is cleared+redirected by middleware.
  const claims = await fetchUserinfo(session);
  const user = mergeUserinfo(claims);
  return <PortalApp user={user} />;
}
