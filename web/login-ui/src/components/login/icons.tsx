import * as React from "react"

type SvgProps = React.SVGProps<SVGSVGElement>

/* ---- Brand: shield + lock (exact paths from the prototype) ---- */
export function BrandMark() {
  return (
    <div className="mb-[22px] flex items-center justify-center gap-2.5">
      <span className="grid size-[38px] place-items-center" aria-hidden>
        <svg
          width="34"
          height="34"
          viewBox="0 0 34 34"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M17 2.5 L29 6.5 V16 C29 24 23.6 29.2 17 31.5 C10.4 29.2 5 24 5 16 V6.5 Z"
            fill="#EE4D2D"
          />
          <path
            d="M17 2.5 L29 6.5 V16 C29 24 23.6 29.2 17 31.5 C10.4 29.2 5 24 5 16 V6.5 Z"
            fill="#FF6633"
            opacity="0.18"
          />
          <rect x="11.5" y="15.5" width="11" height="9" rx="2" fill="#fff" />
          <path
            d="M13.6 15.5 V13 a3.4 3.4 0 0 1 6.8 0 V15.5"
            stroke="#fff"
            strokeWidth="1.8"
            fill="none"
            strokeLinecap="round"
          />
          <circle cx="17" cy="19.4" r="1.5" fill="#EE4D2D" />
          <rect x="16.3" y="19.8" width="1.4" height="3" rx="0.7" fill="#EE4D2D" />
        </svg>
      </span>
      <span className="text-[19px] font-bold tracking-[-0.02em] text-ao-ink">
        Alpha<span className="text-ao-orange">Omega</span>
      </span>
    </div>
  )
}

export function MailIcon(props: SvgProps) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <rect x="3" y="5" width="18" height="14" rx="2.5" />
      <path d="m3.5 7 8.5 6 8.5-6" />
    </svg>
  )
}

export function LockIcon(props: SvgProps) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <rect x="4" y="10.5" width="16" height="10.5" rx="2.5" />
      <path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5" />
    </svg>
  )
}

export function EyeIcon({ off, ...props }: SvgProps & { off?: boolean }) {
  return (
    <svg
      width="19"
      height="19"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      {off ? (
        <path d="M9.9 4.9A9.5 9.5 0 0 1 12 4.7c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4M6.3 6.3A17 17 0 0 0 2 11.7s3.6 7 10 7a9.4 9.4 0 0 0 4.8-1.3M3 3l18 18M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      ) : (
        <>
          <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" />
          <circle cx="12" cy="12" r="3" />
        </>
      )}
    </svg>
  )
}

export function ArrowRightIcon(props: SvgProps) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  )
}

export function ArrowLeftIcon(props: SvgProps) {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M19 12H5M11 18l-6-6 6-6" />
    </svg>
  )
}

export function AlertCircleIcon(props: SvgProps) {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      {...props}
    >
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.5v5M12 16h.01" />
    </svg>
  )
}

export function MfaIcon(props: SvgProps) {
  return (
    <svg
      width="26"
      height="26"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <rect x="6" y="2.5" width="12" height="19" rx="2.5" />
      <path d="M10.5 18.5h3" />
      <path d="M9.5 9.2l1.7 1.7 3.3-3.4" />
    </svg>
  )
}

export function SuccessCheckIcon(props: SvgProps) {
  return (
    <svg
      width="28"
      height="28"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M20 6 9 17l-5-5" />
    </svg>
  )
}

/* ---- SSO brand marks (multicolor — kept verbatim) ---- */
export function GoogleIcon(props: SvgProps) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" {...props}>
      <path
        fill="#4285F4"
        d="M23.04 12.26c0-.81-.07-1.6-.21-2.35H12v4.45h6.19a5.3 5.3 0 0 1-2.3 3.48v2.89h3.72c2.18-2 3.43-4.96 3.43-8.47Z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.11 0 5.72-1.03 7.62-2.79l-3.72-2.89c-1.03.69-2.35 1.1-3.9 1.1-3 0-5.54-2.03-6.45-4.75H1.7v2.98A11.99 11.99 0 0 0 12 24Z"
      />
      <path
        fill="#FBBC05"
        d="M5.55 14.67a7.2 7.2 0 0 1 0-4.6V7.09H1.7a12 12 0 0 0 0 10.56l3.85-2.98Z"
      />
      <path
        fill="#EA4335"
        d="M12 4.75c1.69 0 3.21.58 4.4 1.72l3.3-3.3C17.71 1.2 15.1 0 12 0 7.32 0 3.28 2.69 1.7 7.09l3.85 2.98C6.46 6.78 9 4.75 12 4.75Z"
      />
    </svg>
  )
}

export function MicrosoftIcon(props: SvgProps) {
  return (
    <svg width="17" height="17" viewBox="0 0 23 23" xmlns="http://www.w3.org/2000/svg" {...props}>
      <path fill="#F25022" d="M1 1h10v10H1z" />
      <path fill="#7FBA00" d="M12 1h10v10H12z" />
      <path fill="#00A4EF" d="M1 12h10v10H1z" />
      <path fill="#FFB900" d="M12 12h10v10H12z" />
    </svg>
  )
}
