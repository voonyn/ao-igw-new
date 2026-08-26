import { AuditView, PAGE_SIZE } from "@/components/views/audit";
import { serverRead } from "@/lib/server/console-data";
import type { AuditPage } from "@/lib/console-api";

/**
 * The audit route reads its first page here, during the render, so the feed
 * arrives with the HTML. The view stays a client component: the filters, the
 * pager, the expanded row, and the CSV export are all interactions, and every
 * one of them reads again from the browser.
 */
export default async function AuditRoute() {
  const initial = await serverRead<AuditPage>(`/audit?limit=${PAGE_SIZE}`);
  return <AuditView initial={initial ?? undefined} />;
}
