"use client";

import { Icon } from "./icons";
import { useConsole } from "./store";

const SEVERITY_ICON: Record<string, string> = { success: "check", error: "alert", info: "help" };

export function ToastHost() {
  const { toasts } = useConsole();
  return (
    <div className="toast-wrap" aria-live="polite">
      {toasts.map((t) => (
        <div className={"toast " + t.severity} key={t.id} role={t.severity === "error" ? "alert" : undefined}>
          <span className="tick">
            <Icon name={t.icon || SEVERITY_ICON[t.severity]} size={15} sw={2.6} />
          </span>
          {t.msg}
        </div>
      ))}
    </div>
  );
}
