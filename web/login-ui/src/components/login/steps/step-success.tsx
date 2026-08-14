import { Heading, StepIcon, Subtext } from "../parts"
import { SuccessCheckIcon } from "../icons"

export function StepSuccess() {
  return (
    <div className="pt-2 pb-1.5 text-center">
      <StepIcon ok>
        <SuccessCheckIcon />
      </StepIcon>
      <Heading>You’re signed in</Heading>
      <Subtext className="mb-0">Welcome back to your AlphaOmega portal.</Subtext>
      <span className="mt-[22px] inline-flex items-center gap-2 text-[13px] text-ao-muted">
        <span className="ao-spinner-orange" />
        Redirecting to your dashboard…
      </span>
    </div>
  )
}
