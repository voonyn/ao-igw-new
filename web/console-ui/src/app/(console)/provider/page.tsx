import { ProviderView } from "@/components/views/provider";

/**
 * The provider route reads nothing of its own.
 *
 * The console layout already reads `/provider` server-side and seeds it into
 * `ConsoleProvider`, so the view takes the row from `useConsole()` and the page
 * arrives with the HTML. A second read here would repeat a request the layout
 * already made.
 *
 * The view stays a client component: every knob and the save are interactions.
 */
export default function ProviderRoute() {
  return <ProviderView />;
}
