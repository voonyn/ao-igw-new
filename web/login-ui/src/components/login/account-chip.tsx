export function AccountChip({
  email,
  onChange,
}: {
  email: string
  onChange: () => void
}) {
  const initial = (email.trim().charAt(0) || "A").toUpperCase()
  return (
    <div className="mx-auto mb-6 flex w-fit max-w-full items-center gap-[11px] rounded-full border-[1.5px] border-border bg-ao-field py-2 pr-2 pl-[9px]">
      <span className="grid size-[30px] shrink-0 place-items-center rounded-full bg-primary text-[13px] font-semibold text-white uppercase">
        {initial}
      </span>
      <span className="max-w-[220px] truncate text-[13.5px] font-medium text-ao-ink">
        {email}
      </span>
      <button
        type="button"
        onClick={onChange}
        className="shrink-0 rounded-full px-2 py-1 text-[12.5px] font-semibold text-primary transition-colors hover:bg-[var(--ao-orange-soft)]"
      >
        Change
      </button>
    </div>
  )
}
