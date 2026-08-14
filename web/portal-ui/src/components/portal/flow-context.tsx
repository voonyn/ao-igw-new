"use client";

import { createContext, useContext, type ReactNode } from "react";

import type { PortalUser } from "@/lib/types";

// The authenticated user, resolved server-side from OIDC /userinfo and passed
// down once. Views read it via useUser() the way the mockup read window.AOP.user.
const UserContext = createContext<PortalUser | null>(null);

export function UserProvider({ user, children }: { user: PortalUser; children: ReactNode }) {
  return <UserContext.Provider value={user}>{children}</UserContext.Provider>;
}

export function useUser(): PortalUser {
  const u = useContext(UserContext);
  if (!u) throw new Error("useUser must be used within a UserProvider");
  return u;
}
