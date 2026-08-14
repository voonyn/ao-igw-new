"use client";

import { use } from "react";
import { DetailRoute, useBackTo, useRecord } from "@/components/console/detail-route";
import { useConsole } from "@/components/console/store";
import { ProjectDetailPage } from "@/components/views/projects";
import { byId, canWriteOrg } from "@/lib/console-api";
import type { Project } from "@/lib/types";

export default function ProjectDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { me, A } = useConsole();
  const { state, reload } = useRecord<Project>(byId.project, id);
  const back = useBackTo("/projects");

  return (
    <DetailRoute state={state} reload={reload} resource="project">
      {(project) => (
        <ProjectDetailPage
          project={project}
          A={A}
          canWrite={canWriteOrg(me, project.orgId, ["ORG_OWNER", "ORG_PROJECT_OWNER"])}
          onClose={back}
          onChanged={reload}
        />
      )}
    </DetailRoute>
  );
}
