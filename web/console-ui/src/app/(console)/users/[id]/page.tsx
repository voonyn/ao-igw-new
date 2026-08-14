"use client";

import { use } from "react";
import { DetailRoute, useBackTo, useRecord } from "@/components/console/detail-route";
import { useConsole } from "@/components/console/store";
import { UserDetailPage } from "@/components/views/users";
import { byId, canWriteOrg } from "@/lib/console-api";
import type { User } from "@/lib/types";

export default function UserDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { me, A } = useConsole();
  const { state, reload } = useRecord<User>(byId.user, id);
  const back = useBackTo("/users");

  return (
    <DetailRoute state={state} reload={reload} resource="user">
      {(user) => (
        <UserDetailPage
          user={user}
          A={A}
          canWrite={canWriteOrg(me, user.orgId, ["ORG_OWNER", "ORG_USER_MANAGER"])}
          onClose={back}
          onChanged={reload}
        />
      )}
    </DetailRoute>
  );
}
