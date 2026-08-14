"use client"

import * as React from "react"
import { usePathname } from "next/navigation"

import { BrandMark } from "@/components/login/icons"
import { ProgressPips } from "@/components/login/progress-pips"
import {
  LoginFlowProvider,
  useLoginFlow,
} from "@/components/login/flow-context"

const STEP_BY_PATH: Record<string, number> = {
  "/identifier": 1,
  "/password": 2,
  "/verify": 3,
  "/success": 4,
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
