"use client"

import * as React from "react"

import { StepIdentify } from "@/components/login/steps/step-identify"
import { useLoginFlow } from "@/components/login/flow-context"
import { messageForError } from "@/lib/login-client"
import { cn } from "@/lib/utils"
import { checkIdentifier } from "./actions"
import { QRPanel } from "./qr-panel"

export function IdentifierClient({
  authRequest,
  redirectUri,
  digitalIdentity,
}: {
  authRequest: string
  redirectUri: string
  /** Whether this deployment runs a Scan Verifier, read on the server from the
   *  capability endpoint. With it off, this page renders as it always has. */
  digitalIdentity: boolean
}) {
  const { email, setEmail, setAuthRequest, setRedirectUri, navigate } = useLoginFlow()
  const [tab, setTab] = React.useState<"password" | "scan">("password")

  // Carry the authRequest through the multi-step flow (persisted in the flow
  // context so /password and /success can finalize against it).
  React.useEffect(() => {
    setAuthRequest(authRequest)
  }, [authRequest, setAuthRequest])

  // Carry the (already server-validated) post-login return URL the same way, so
  // /success can hand the browser to it when there is no OIDC request to finalize.
  React.useEffect(() => {
    setRedirectUri(redirectUri)
  }, [redirectUri, setRedirectUri])

  const identify = (
    <StepIdentify
      initialEmail={email}
      onContinue={async (value) => {
        const result = await checkIdentifier(value)
        if (!result.ok) return messageForError(result.error)
        setEmail(value)
        navigate("/password", "forward")
        return null
      }}
    />
  )

  if (!digitalIdentity) return identify

  return (
    <>
      <div role="tablist" className="mb-[22px] grid grid-cols-2 gap-1 rounded-[10px] bg-ao-field p-1">
        <Tab selected={tab === "password"} onSelect={() => setTab("password")}>
          Email
        </Tab>
        <Tab selected={tab === "scan"} onSelect={() => setTab("scan")}>
          Scan
        </Tab>
      </div>
      {tab === "password" ? identify : <QRPanel />}
    </>
  )
}

function Tab({
  selected,
  onSelect,
  children,
}: {
  selected: boolean
  onSelect: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={selected}
      onClick={onSelect}
      className={cn(
        "h-9 rounded-[8px] text-[13.5px] font-medium transition-colors",
        selected ? "bg-white text-ao-label shadow-sm" : "text-ao-muted hover:text-ao-label",
      )}
    >
      {children}
    </button>
  )
}
