"use client";

import { useBackTo } from "@/components/console/detail-route";
import { CreateProjectPage } from "@/components/views/projects";

export default function NewProject() {
  return <CreateProjectPage onClose={useBackTo("/projects")} />;
}
