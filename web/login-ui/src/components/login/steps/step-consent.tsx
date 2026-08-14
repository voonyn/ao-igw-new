"use client"

import * as React from "react"

import { Button } from "@/components/ui/button"
import { Heading, PrimaryButton, StepIcon, Subtext } from "../parts"
import type { ScopeConsent } from "@/app/(login)/success/actions"

// StepConsent renders the requested scopes — each with its description and the
// claims it releases — and Approve / Deny (all-or-nothing v1). It is reached when
// /complete reports a non-first-party client without prior consent.
export function StepConsent({
  scopes,
  loading,
  onApprove,
  onDeny,
}: {
  scopes: ScopeConsent[]
  loading: boolean
  onApprove: () => void
  onDeny: () => void
}) {
  return (
    <div className="pt-1">
      <StepIcon>
        <ShieldIcon />
      </StepIcon>
      <Heading>Authorize access</Heading>
      <Subtext>
        An application is requesting access to your account. Review what it will
        be able to see, then approve or cancel.
      </Subtext>

      <ul className="mb-6 flex flex-col gap-3">
        {scopes.map((s) => (
          <li
            key={s.name}
            className="rounded-[10px] border-[1.5px] border-input bg-ao-field px-4 py-3"
          >
            <p className="text-[14px] font-semibold text-ao-ink">
              {s.displayName || s.name}
            </p>
            {s.description && (
              <p className="mt-0.5 text-[13px] text-ao-muted">{s.description}</p>
            )}
            {s.claims.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {s.claims.map((claim) => (
                  <span
                    key={claim}
                    className="rounded-full bg-white px-2 py-0.5 text-[11.5px] font-medium text-ao-muted ring-1 ring-input"
                  >
                    {claim}
                  </span>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>

      <PrimaryButton
        type="button"
        loading={loading}
        loadingLabel="Authorizing…"
        onClick={onApprove}
      >
        Allow access
      </PrimaryButton>
      <Button
        type="button"
        variant="outline"
        disabled={loading}
        onClick={onDeny}
        className="mt-2.5 h-12 w-full rounded-[10px] border-[1.5px] border-input bg-white text-[14px] font-medium text-ao-label hover:bg-[#FFFBFA]"
      >
        Cancel
      </Button>
    </div>
  )
}

function ShieldIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}
