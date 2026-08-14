"use client";

import { use } from "react";
import { DetailRoute, useBackTo, useRecord } from "@/components/console/detail-route";
import { useConsole } from "@/components/console/store";
import { AppDetailPage } from "@/components/views/applications";
import { byId, canWriteOrg } from "@/lib/console-api";
import type { App } from "@/lib/types";

export default function ApplicationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { me, A } = useConsole();
  const { state, reload } = useRecord<App>(byId.app, id);
  const back = useBackTo("/applications");

  return (
    <DetailRoute state={state} reload={reload} resource="application">
      {(app) => (
        // The app's org comes from its parent project and rides on the record —
        // there is no projects collection left to resolve it against, and the
        // gateway re-checks the write anyway.
        <AppDetailPage
          app={app}
          A={A}
          canWrite={canWriteOrg(me, app.orgId, ["ORG_OWNER", "ORG_PROJECT_OWNER"])}
          onClose={back}
          onChanged={reload}
        />
      )}
    </DetailRoute>
  );
}
