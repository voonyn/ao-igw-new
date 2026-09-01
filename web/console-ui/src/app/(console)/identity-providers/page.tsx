import { IdentityProvidersView } from "@/components/views/identity-providers";
import { serverRead } from "@/lib/server/console-data";
import type { IdentityProvider } from "@/lib/console-api";

/**
 * The identity-provider route reads the tenant's directories here, during the
 * render, so the list arrives with the HTML.
 *
 * The view stays a client component: the form, the connection test, and every
 * write are interactions. The list is bounded and answers whole, so there is no
 * page to seed beyond this one read.
 */
export default async function IdentityProvidersRoute() {
  const initial = await serverRead<IdentityProvider[]>("/identity-providers");
  return <IdentityProvidersView initial={initial ?? undefined} />;
}
