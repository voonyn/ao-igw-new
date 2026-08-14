"use client";

import { useBackTo } from "@/components/console/detail-route";
import { CreateUserPage } from "@/components/views/users";

export default function NewUser() {
  return <CreateUserPage onClose={useBackTo("/users")} />;
}
