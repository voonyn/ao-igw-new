"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon } from "./icons";
import { useCrumbTail } from "./page-head";
import { useConsole } from "./store";
import { PAGE_PATH, PAGE_TITLES, pageIdFromPath } from "@/lib/helpers";

/** Anything that is not production is styled as not-production. The value is
 * free text (an operator may run "eu-staging"), so the test is on the one word
 * that must not be claimed falsely rather than on an enum we would have to keep
 * in step with every deployment's naming. */
const isProdEnv = (env: string) => /^prod/i.test(env.trim());

export function Topbar({ env }: { env?: string }) {
  const { db, tenantId, theme, toggleTheme } = useConsole();
  const pathname = usePathname();
  const tail = useCrumbTail();
  const tenant = db.tenants.find((t) => t.id === tenantId) || db.tenants[0];
  const pageId = pageIdFromPath(pathname);
  const title = PAGE_TITLES[pageId] || "Overview";

  return (
    <header className="topbar">
      <nav className="crumb" aria-label="Breadcrumb">
        <ol>
          <li>
            <Link href={PAGE_PATH.overview}>{tenant.name}</Link>
            <Icon name="chevR" size={13} sw={2} />
          </li>
          {/* The route's own segment is a link only while something follows it —
              a link to the page you are already on is a dead control. */}
          {tail ? (
            <li>
              <Link href={PAGE_PATH[pageId] ?? PAGE_PATH.overview}>{title}</Link>
              <Icon name="chevR" size={13} sw={2} />
            </li>
          ) : (
            <li aria-current="page">
              <b>{title}</b>
            </li>
          )}
          {tail && (
            <li aria-current="page">
              <b>{tail}</b>
            </li>
          )}
        </ol>
      </nav>
      <span className="spacer" />
      {/* Unset renders nothing. Never a default: a badge that reads
          "Production" because nobody configured it is the bug being fixed. */}
      {env && (
        <span className={"env-pill" + (isProdEnv(env) ? "" : " alt")}>
          <span className="dot" />
          {env}
        </span>
      )}
      <button
        type="button"
        className="icon-btn"
        aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        onClick={toggleTheme}
      >
        <Icon name={theme === "dark" ? "sun" : "moon"} size={18} />
      </button>
    </header>
  );
}
