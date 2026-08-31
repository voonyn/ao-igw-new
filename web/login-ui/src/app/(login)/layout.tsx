"use client"

import * as React from "react"
import { usePathname } from "next/navigation"

import { BrandMark } from "@/components/login/icons"
import { ProgressPips } from "@/components/login/progress-pips"
import {
  LoginFlowProvider,
  useLoginFlow,
} from "@/components/login/flow-context"

// The sign-in flow, one entry per screen. `/verify`, `/passkey` and `/enroll`
// are one step and share pip 3: they are the Second Factor, and a person who
// switches Factor mid sign-in must not watch the bar run backwards.
//
// The other routes under `(login)` are absent on purpose, and the fallback
// gives them pip 1. `forgot`, `reset`, `accept-invite` and `verify-email` are
// each a flow of their own that a link starts, so the screen a person lands on
// is the first screen they see. `change-password` is named because it is not:
// `/success` routes to it when the gateway forces a change, and it is the last
// thing the person does, so it holds the last pip instead of jumping back.
const STEP_BY_PATH: Record<string, number> = {
  "/identifier": 1,
  "/password": 2,
  "/verify": 3,
  "/passkey": 3,
  "/enroll": 3,
  "/success": 4,
  "/change-password": 4,
}

function Card({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const { direction } = useLoginFlow()
  const step = STEP_BY_PATH[pathname] ?? 1

  return (
    <main
      role="main"
      className="ao-card relative z-[1] w-[480px] max-w-full rounded-[14px] bg-white px-10 pt-10 pb-7 max-[520px]:flex max-[520px]:min-h-screen max-[520px]:w-full max-[520px]:flex-col max-[520px]:justify-center max-[520px]:rounded-none max-[520px]:px-4 max-[520px]:pt-[52px] max-[520px]:pb-8 max-[520px]:shadow-none"
    >
      <BrandMark />
      <ProgressPips step={step} />

      <div className="relative">
        {/* keyed by route so the directional entrance animation replays per step */}
        <div
          key={pathname}
          className={direction === "back" ? "ao-step-in-back" : "ao-step-in"}
        >
          {children}
        </div>
      </div>
    </main>
  )
}

export default function LoginLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <LoginFlowProvider>
      <div className="ao-bg-glow" aria-hidden />
      <div className="ao-bg-pattern" aria-hidden />
      <Card>{children}</Card>
    </LoginFlowProvider>
  )
}
