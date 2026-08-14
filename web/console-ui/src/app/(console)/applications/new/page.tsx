"use client";

import { useBackTo } from "@/components/console/detail-route";
import { CreateAppPage } from "@/components/views/applications";

export default function NewApplication() {
  return <CreateAppPage onClose={useBackTo("/applications")} />;
}
