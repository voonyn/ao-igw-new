"use client";

import { useBackTo } from "@/components/console/detail-route";
import { CreateOrgPage } from "@/components/views/organizations";

export default function NewOrganization() {
  return <CreateOrgPage onClose={useBackTo("/organizations")} />;
}
