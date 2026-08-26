import { SessionsView } from "@/components/views/sessions";
import { serverRead } from "@/lib/server/console-data";
import type { Grant, LoginSession, Page } from "@/lib/types";

/** Rows per page on both tabs. It is `usePagedList`'s own default, and the two
 * have to agree: a seeded page of a different size than the hook then asks for
 * would make page two overlap page one. */
const PAGE_SIZE = 50;

/**
 * The sessions route reads the first page of both tabs here, during the render,
 * so the tables arrive with the HTML.
 *
 * The view stays a client component: the tabs, the pager, the filters and the
 * revoke are all interactions, and every one of them reads again from the
 * browser. Both reads run together, because neither needs the other's answer.
 */
export default async function SessionsRoute() {
  const [sessions, grants] = await Promise.all([
    serverRead<Page<LoginSession>>(`/sessions?limit=${PAGE_SIZE}`),
    serverRead<Page<Grant>>(`/grants?limit=${PAGE_SIZE}`),
  ]);
  return <SessionsView initial={{ sessions: sessions ?? undefined, grants: grants ?? undefined }} />;
}
