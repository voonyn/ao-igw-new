import { cn } from "@/lib/utils"

export function ProgressPips({ step }: { step: number }) {
  // success (step 4) caps at the 3rd stage
  const current = Math.min(step, 3)
  return (
    <div
      className="mb-[26px] flex items-center justify-center gap-[7px]"
      aria-hidden
    >
      {[1, 2, 3].map((n) => {
        const active = n === current
        const done = n < current
        return (
          <span
            key={n}
            className={cn(
              "h-[5px] rounded-full transition-[background-color,width] duration-300",
              active
                ? "w-[30px] bg-primary"
                : done
                  ? "w-[22px] bg-[rgba(238,77,45,0.4)]"
                  : "w-[22px] bg-border"
            )}
          />
        )
      })}
    </div>
  )
}
