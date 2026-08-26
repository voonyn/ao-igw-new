import { NotificationsView } from "@/components/views/notifications";
import { serverRead } from "@/lib/server/console-data";
import type { NotificationSettings, NotificationTemplateInfo } from "@/lib/console-api";

/**
 * The notifications route reads the tenant delivery settings and the tenant
 * template list here, during the render, so both arrive with the HTML.
 *
 * The view stays a client component: the scope selector, the template editor,
 * the preview and the test send are interactions, and picking an organization
 * reads that scope from the browser. Only the tenant scope is seeded, because
 * only the tenant scope is the one the page opens on.
 *
 * The template list is passed as a plain array. Its client reader answers a bare
 * value and not an outcome, so a refusal here seeds nothing and the view reads
 * it again and states the refusal itself.
 */
export default async function NotificationsRoute() {
  const [settings, templates] = await Promise.all([
    serverRead<NotificationSettings>("/notifications/settings"),
    serverRead<NotificationTemplateInfo[]>("/notifications/templates"),
  ]);
  return (
    <NotificationsView
      initial={{
        settings: settings ?? undefined,
        templates: templates?.ok ? templates.data : undefined,
      }}
    />
  );
}
