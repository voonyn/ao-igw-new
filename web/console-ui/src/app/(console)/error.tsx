"use client";

// Segment-level boundary for the whole console group. A render or data error in
// any console page lands here instead of a blank shell, and `reset` re-renders
// the segment without a full page reload.

import { useEffect } from "react";

export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error("console: unhandled error in console segment", error);
  }, [error]);

  return (
    <div className="fade-in">
      <div className="page-head">
        <div>
          <h1>Something broke in this view</h1>
          <div className="sub">
            The rest of the console is still usable — this page failed on its own. If it keeps failing, check the admin
            API and the browser console.
          </div>
        </div>
      </div>
      <div className="card view-notice" role="alert">
        <div style={{ minWidth: 0, flex: 1 }}>
          <b>{error.message || "Unexpected error"}</b>
          {error.digest ? <p style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>digest {error.digest}</p> : null}
        </div>
        <button type="button" className="btn primary sm" onClick={reset}>
          Try again
        </button>
      </div>
    </div>
  );
}
