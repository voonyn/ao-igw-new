import { PoliciesView } from "@/components/views/policies";
import { serverRead } from "@/lib/server/console-data";
import type { AuthPolicy } from "@/lib/console-api";

/**
 * The policies route reads the tenant default here, during the render, so the
 * form arrives with the HTML.
 *
 * The view stays a client component: the scope selector, every field, and the
 * save are interactions, and picking an organization reads that override from
 * the browser. Only the tenant scope is seeded, because only the tenant scope is
 * the one the page opens on.
 */
export default async function PoliciesRoute() {
  const initial = await serverRead<AuthPolicy>("/settings/auth");
  return <PoliciesView initial={initial ?? undefined} />;
}
