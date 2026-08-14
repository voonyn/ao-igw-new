"use client";

import { useCallback, useEffect, useState } from "react";

import { Icon } from "../icons";
import { PageHead, KV, Seg, NotWiredBanner } from "../primitives";
import { presentActivity } from "@/lib/activity";
import { accountErrorFrom, type AccountErr } from "@/lib/format";
import type { Actions, ActivityEvent, ActivityEventWire } from "@/lib/types";

// One of the page sizes the account API serves (10 / 50 / 100); anything else is
// refused, not resized.
const PAGE_SIZE = 50;

// AlphaOmega User Portal — Activity (NotificationsDrawer lives in the shell, not here)
//
// The timeline is LIVE: it reads the caller's own audit feed from the account API
// through the BFF (/api/account/activity → gateway /api/v1/account/activity),
// which scopes it to the token `sub`. The side cards ("This week" counters, the
// security-tip card) and Export are still placeholder — they need aggregation the
// feed API deliberately does not do.
export function ActivityView({ A }: { A: Actions }) {
  const [filter, setFilter] = useState("all");
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [cursor, setCursor] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [err, setErr] = useState<AccountErr>("");

  // loadPage fetches one keyset page. An empty `after` starts at the head and
  // replaces the list; a cursor appends the next older page. The cursor is opaque
  // — it is echoed back to the gateway verbatim, never parsed here.
  const loadPage = useCallback(async function (after: string) {
    try {
      const q = new URLSearchParams({ limit: String(PAGE_SIZE) });
      if (after) q.set("cursor", after);
      const res = await fetch("/api/account/activity?" + q.toString(), { headers: { Accept: "application/json" } });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 200) {
        const page = (Array.isArray(data.events) ? data.events : []) as ActivityEventWire[];
        const rows = page.map(presentActivity);
        setEvents(function (prev) { return after ? prev.concat(rows) : rows; });
        setCursor(typeof data.nextCursor === "string" ? data.nextCursor : "");
        setErr("");
      } else {
        setErr(accountErrorFrom(res.status, data && data.error));
      }
    } catch {
      setErr("error");
    }
  }, []);

  // Fetch the first page on mount inside an async IIFE so no setState runs
  // synchronously in the effect body.
  useEffect(function () {
    void (async function () {
      await loadPage("");
      setLoading(false);
    })();
  }, [loadPage]);

  async function loadMore() {
    if (!cursor) return;
    setLoadingMore(true);
    try {
      await loadPage(cursor);
    } finally {
      setLoadingMore(false);
    }
  }

  // The segment narrows what has already been loaded; it never gates paging, so a
  // filtered view that looks sparse can still be extended with "Load more".
  const shown = events.filter(function (e) {
    if (filter === "all") return true;
    if (filter === "security") return ["signin", "newdevice", "mfa", "password"].indexOf(e.type) !== -1;
    if (filter === "account") return ["profile", "access", "consent"].indexOf(e.type) !== -1;
    return true;
  });

  return (
    <div className="fade-in">
      <PageHead title="Activity" sub="A timeline of sign-ins, security changes and account updates.">
        <button type="button" className="btn ghost" onClick={function () { A.toast("Activity exported", "download"); }}><Icon name="download" size={15} sw={2} />Export</button>
      </PageHead>
      <NotWiredBanner>The timeline below is live from your account&rsquo;s security log. The &ldquo;This week&rdquo; counters, the security tip and Export are still placeholder &mdash; they need aggregation the feed API doesn&rsquo;t provide yet.</NotWiredBanner>

      <div className="col-2">
        {/* Timeline — LIVE via /api/account/activity */}
        <div className="card">
          <div className="card-head">
            <span className="card-title">Recent activity</span>
            <span className="spacer"></span>
            <Seg options={[{ value: "all", label: "All" }, { value: "security", label: "Security" }, { value: "account", label: "Account" }]} value={filter} onChange={setFilter} />
          </div>
          <div className="card-pad" style={{ paddingTop: 18 }}>
            {err && (
              <div style={{ marginBottom: 12, fontSize: 13, color: err === "reauth" ? "var(--error)" : err === "unavailable" ? "var(--muted)" : "var(--warn)" }}>
                {err === "reauth" && <>Your session is no longer valid. <a href="/auth/login" style={{ color: "var(--accent)", fontWeight: 600 }}>Sign in again</a></>}
                {err === "rate" && "Too many requests. Please wait a minute and try again."}
                {/* The feed is an optional gateway sub-feature (mountAccount) — a 404
                    means it was never mounted, which is a fact to state, not a failure. */}
                {err === "unavailable" && "Activity history isn’t available on this server."}
                {err === "error" && "Could not load your activity. Please try again in a moment."}
              </div>
            )}
            {loading && <div style={{ fontSize: 13, color: "var(--muted)" }}>Loading activity…</div>}
            {!loading && events.length === 0 && !err && (
              <div style={{ fontSize: 13, color: "var(--muted)" }}>No activity yet. Sign-ins and security changes will appear here.</div>
            )}
            {!loading && events.length > 0 && shown.length === 0 && (
              <div style={{ fontSize: 13, color: "var(--muted)" }}>Nothing in this category yet{cursor ? " — load more to keep looking." : "."}</div>
            )}
            <div className="timeline">
              {shown.map(function (e) {
                return (
                  <div key={e.id} className="tl-item">
                    <div className="tl-rail"><span className={"tl-node " + e.tone}><Icon name={e.icon} size={16} sw={2} /></span></div>
                    <div className="tl-main">
                      <div className="tl-ttl">{e.title}{e.tone === "warn" && <span className="badge amber"><Icon name="alert" size={11} sw={2.4} />Review</span>}<span className="tl-time">{e.time}</span></div>
                      <div className="tl-sub">{e.detail}</div>
                    </div>
                  </div>
                );
              })}
            </div>
            {/* Paging is driven only by nextCursor, never by the active filter. */}
            {cursor && (
              <button type="button" className="btn ghost" style={{ width: "100%", marginTop: 14 }} onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? "Loading…" : "Load more"}
              </button>
            )}
          </div>
        </div>

        {/* Side: notifications + tip */}
        <div className="stack">
          <div className="card card-pad">
            <span className="sect-title"><Icon name="alert" size={13} sw={2} />Security tip</span>
            <div className="lrow" style={{ paddingTop: 6, borderBottom: "none" }}>
              <span className="licon accent"><Icon name="laptop" size={18} sw={2} /></span>
              <div className="lmain"><div className="lttl">New device in Austin, US</div><div className="lsub">If this wasn’t you, secure your account now.</div></div>
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <button type="button" className="btn ghost sm" style={{ flex: 1 }} onClick={function () { A.toast("Marked as safe"); }}>That was me</button>
              <button type="button" className="btn danger-ghost sm" style={{ flex: 1 }} onClick={function () { A.nav("security"); }}>Secure account</button>
            </div>
          </div>

          <div className="card card-pad">
            <span className="sect-title"><Icon name="globe" size={13} sw={2} />This week</span>
            <KV k="Sign-ins" v="38" />
            <KV k="New devices" v="1" />
            <KV k="Failed attempts" v={<span style={{ color: "var(--success)" }}>0</span>} />
            <KV k="Apps accessed" v="7" />
          </div>
        </div>
      </div>
    </div>
  );
}
