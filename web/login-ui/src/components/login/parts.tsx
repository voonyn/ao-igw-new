import * as React from "react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { AlertCircleIcon, ArrowLeftIcon, ArrowRightIcon } from "./icons"

/* ---- Typography ---- */
export function Heading({ children }: { children: React.ReactNode }) {
  return (
    <h1 className="text-center text-[28px] font-semibold tracking-[-0.02em] text-ao-ink max-[520px]:text-[25px]">
      {children}
    </h1>
  )
}

export function Subtext({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <p
      className={cn(
        "mt-2 mb-[26px] text-center text-[14.5px] text-pretty text-ao-muted [&_strong]:font-semibold [&_strong]:text-ao-ink",
        className
      )}
    >
      {children}
    </p>
  )
}

/* ---- Text field: label + lead icon + input + inline error ---- */
const FIELD_INPUT =
  "h-12 w-full border-[1.5px] border-input bg-ao-field py-0 pr-3.5 pl-11 text-[14.5px] text-ao-ink transition-[border-color,box-shadow,background-color] " +
  "placeholder:text-ao-muted-2 md:text-[14.5px] " +
  "focus-visible:border-primary focus-visible:bg-white focus-visible:ring-4 focus-visible:ring-[var(--ao-orange-soft)] " +
  "aria-invalid:border-destructive aria-invalid:bg-ao-error-bg aria-invalid:ring-0 " +
  "focus-visible:aria-invalid:border-destructive focus-visible:aria-invalid:ring-4 focus-visible:aria-invalid:ring-destructive/15"

type TextFieldProps = Omit<React.ComponentProps<"input">, "className"> & {
  label: string
  icon: React.ReactNode
  error?: string | null
  trailing?: React.ReactNode
  inputClassName?: string
}

export function TextField({
  id,
  label,
  icon,
  error,
  trailing,
  inputClassName,
  ...inputProps
}: TextFieldProps) {
  const invalid = Boolean(error)
  return (
    <div className="group/field">
      <Label
        htmlFor={id}
        className="mb-[7px] block text-[13px] font-medium text-ao-label"
      >
        {label}
      </Label>
      <div className="relative flex items-center">
        <span
          className={cn(
            "pointer-events-none absolute left-3.5 z-10 grid place-items-center transition-colors",
            invalid
              ? "text-ao-error"
              : "text-ao-muted-2 group-focus-within/field:text-ao-orange"
          )}
          aria-hidden
        >
          {icon}
        </span>
        <Input
          id={id}
          aria-invalid={invalid}
          className={cn(FIELD_INPUT, trailing && "pr-[46px]", inputClassName)}
          {...inputProps}
        />
        {trailing}
      </div>
      {invalid && (
        <p className="mt-1.5 flex items-center gap-[5px] text-[12.5px] font-medium text-ao-error">
          <AlertCircleIcon className="size-[13px]" />
          <span>{error}</span>
        </p>
      )}
    </div>
  )
}

/* ---- Primary CTA (orange) ---- */
const PRIMARY_BTN =
  "mt-1 h-[50px] w-full gap-2.5 rounded-[10px] bg-primary text-[15px] font-semibold text-white shadow-[0_6px_16px_rgba(238,77,45,0.28)] " +
  "transition-[background-color,transform,box-shadow] hover:bg-ao-orange-bright hover:-translate-y-px hover:shadow-[0_10px_22px_rgba(238,77,45,0.34)] " +
  "active:translate-y-0 active:shadow-[0_4px_12px_rgba(238,77,45,0.28)] disabled:translate-y-0 disabled:opacity-90"

export function PrimaryButton({
  loading,
  loadingLabel,
  children,
  className,
  ...props
}: React.ComponentProps<typeof Button> & {
  loading?: boolean
  loadingLabel?: string
}) {
  return (
    <Button
      type="submit"
      disabled={loading}
      className={cn(PRIMARY_BTN, className)}
      {...props}
    >
      <span>{loading ? loadingLabel : children}</span>
      {loading ? (
        <span className="ao-spinner" />
      ) : (
        <ArrowRightIcon className="size-[18px] transition-transform group-hover/button:translate-x-[3px]" />
      )}
    </Button>
  )
}

/* ---- SSO button (white, outline) ---- */
const SSO_BTN =
  "h-12 w-full gap-2.5 rounded-[10px] border-[1.5px] border-input bg-white text-[14px] font-medium text-ao-label " +
  "transition-[border-color,background-color,transform,box-shadow] hover:border-primary hover:bg-[#FFFBFA] hover:text-ao-label hover:-translate-y-px hover:shadow-[0_6px_14px_rgba(238,77,45,0.10)] active:translate-y-0"

export function SsoButton({
  icon,
  children,
  className,
  ...props
}: React.ComponentProps<typeof Button> & { icon: React.ReactNode }) {
  return (
    <Button
      type="button"
      variant="outline"
      className={cn(SSO_BTN, className)}
      {...props}
    >
      {icon}
      {children}
    </Button>
  )
}

/* ---- Inline text link (orange) ---- */
export function LinkButton({
  className,
  ...props
}: React.ComponentProps<"button">) {
  return (
    <button
      type="button"
      className={cn(
        "rounded-none text-[13.5px] font-medium text-primary transition-colors hover:text-ao-orange-bright hover:underline",
        className
      )}
      {...props}
    />
  )
}

/* ---- Back link (muted, with arrow) ---- */
export function BackLink({
  onClick,
  children = "Back",
}: {
  onClick: () => void
  children?: React.ReactNode
}) {
  return (
    <div className="flex justify-center">
      <button
        type="button"
        onClick={onClick}
        className="mx-auto mt-[22px] inline-flex items-center gap-1.5 text-[13.5px] font-medium text-ao-muted transition-colors hover:text-ao-orange"
      >
        <ArrowLeftIcon />
        {children}
      </button>
    </div>
  )
}

/* ---- "or continue with" divider ---- */
export function Divider({ children }: { children: React.ReactNode }) {
  return (
    <div className="my-[22px] flex items-center gap-3.5 text-[12.5px] font-medium text-ao-muted-2">
      <Separator className="flex-1" />
      {children}
      <Separator className="flex-1" />
    </div>
  )
}

/* ---- Footer links ---- */
export function Footer() {
  return (
    <p className="mt-[26px] text-center text-[12.5px] text-ao-muted-2">
      <a
        href="#"
        className="text-ao-muted transition-colors hover:text-ao-orange"
      >
        Contact IT Support
      </a>
      <span className="mx-2 text-border">·</span>
      <a
        href="#"
        className="text-ao-muted transition-colors hover:text-ao-orange"
      >
        Privacy Policy
      </a>
    </p>
  )
}

/* ---- Rounded header icon (MFA / success) ---- */
export function StepIcon({
  ok,
  children,
}: {
  ok?: boolean
  children: React.ReactNode
}) {
  return (
    <div
      className={cn(
        "mx-auto mb-[18px] grid size-14 place-items-center rounded-[14px]",
        ok
          ? "bg-[rgba(31,157,91,0.12)] text-ao-success"
          : "bg-[var(--ao-orange-soft)] text-ao-orange"
      )}
      aria-hidden
    >
      {children}
    </div>
  )
}
