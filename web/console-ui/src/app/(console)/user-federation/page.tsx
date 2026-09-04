import { UserFederationView } from "@/components/views/user-federation";
import { serverRead } from "@/lib/server/console-data";
import type { Federation } from "@/lib/console-api";

/**
 * The user-federation route reads the tenant's directories here, during the
 * render, so the list arrives with the HTML.
 *
 * The view stays a client component: the form, the connection test, and every
 * write are interactions. The list is bounded and answers whole, so there is no
 * page to seed beyond this one read.
 */
export default async function UserFederationRoute() {
  const initial = await serverRead<Federation[]>("/user-federations");
  return <UserFederationView initial={initial ?? undefined} />;
}
