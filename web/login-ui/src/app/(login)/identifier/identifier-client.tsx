"use client"

import * as React from "react"

import { StepIdentify } from "@/components/login/steps/step-identify"
import { useLoginFlow } from "@/components/login/flow-context"
import { messageForError } from "@/lib/login-client"
import { checkIdentifier } from "./actions"

export function IdentifierClient({
  authRequest,
  redirectUri,
}: {
  authRequest: string
  redirectUri: string
}) {
  const { email, setEmail, setAuthRequest, setRedirectUri, navigate } = useLoginFlow()

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

  return (
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
}
