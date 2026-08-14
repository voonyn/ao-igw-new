"use client";

import { use } from "react";
import { DetailRoute, useBackTo, useRecord } from "@/components/console/detail-route";
import { useConsole } from "@/components/console/store";
import { OrgDetailPage } from "@/components/views/organizations";
import { byId, canWriteOrg } from "@/lib/console-api";
import type { Org } from "@/lib/types";

export default function OrganizationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { me, A } = useConsole();
  const { state, reload } = useRecord<Org>(byId.org, id);
  const back = useBackTo("/organizations");

  return (
    <DetailRoute state={state} reload={reload} resource="organization">
      {(org) => (
        <OrgDetailPage
          org={org}
          A={A}
          canWrite={canWriteOrg(me, org.id, ["ORG_OWNER"])}
          onClose={back}
          onChanged={reload}
        />
      )}
    </DetailRoute>
  );
}
