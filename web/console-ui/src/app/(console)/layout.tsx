import { Suspense } from "react";
import { ConsoleProvider } from "@/components/console/store";
import { CrumbProvider } from "@/components/console/page-head";
import { Sidebar } from "@/components/console/sidebar";
import { Topbar } from "@/components/console/topbar";
import { ToastHost } from "@/components/console/toast";
import { ConfirmHost } from "@/components/console/primitives";

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  // Server-only, per the console's no-NEXT_PUBLIC_ policy: read here and handed
  // down as a prop rather than inlined into the client bundle. Unset stays
  // undefined all the way to the badge, which then renders nothing.
  const env = process.env.AO_CONSOLE_ENV?.trim() || undefined;
  return (
    <ConsoleProvider>
      <CrumbProvider>
        <div className="shell">
          {/* First focusable element in the document, so Tab on a fresh page
              offers it before the whole sidebar. */}
          <a className="skip-link" href="#content">
            Skip to main content
          </a>
          <Sidebar />
          <div className="main">
            <Topbar env={env} />
            <main id="content" className="content" tabIndex={-1}>
              <div className="content-inner">
                {/* Table state lives in the URL, so every list view reads
                    `useSearchParams`. One boundary here is what keeps that from
                    opting each route out of prerendering. */}
                <Suspense fallback={null}>{children}</Suspense>
              </div>
            </main>
          </div>
          <ToastHost />
          <ConfirmHost />
        </div>
      </CrumbProvider>
    </ConsoleProvider>
  );
}
