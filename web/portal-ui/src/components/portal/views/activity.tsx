"use client";

import { useEffect, useState } from "react";

import { Icon } from "../icons";
import { PageHead, KV, Seg, NotWiredBanner } from "../primitives";
import { presentActivity } from "@/lib/activity";
import { accountErrorFrom, type AccountErr } from "@/lib/format";
import type { Actions, ActivityEvent, ActivityEventWire } from "@/lib/types";

// The rows one page carries. The gateway clamps a limit above 100, so this value
// is inside what the account API serves.
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
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<AccountErr>("");

  // The feed pages by offset, so one page replaces the list rather than
  // extending it. `total` counts the whole feed, and the pager is derived from
  // it, so the last page is known before the reader reaches it.
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // loadPage fetches one page by number. Page 1 is the newest.
  useEffect(function () {
    let live = true;
    // Every setState runs inside the async IIFE, so none of them runs
    // synchronously in the effect body.
    void (async function () {
      setLoading(true);
      try {
        const q = new URLSearchParams({ limit: String(PAGE_SIZE), page: String(page) });
        const res = await fetch("/api/account/activity?" + q.toString(), { headers: { Accept: "application/json" } });
        const data = await res.json().catch(function () { return {}; });
        if (!live) return;
        if (res.status === 200) {
          const rows = (Array.isArray(data.events) ? data.events : []) as ActivityEventWire[];
          setEvents(rows.map(presentActivity));
          setTotal(typeof data.total === "number" ? data.total : 0);
          setErr("");
        } else {
          setErr(accountErrorFrom(res.status, data && data.error));
        }
      } catch {
        if (live) setErr("error");
      } finally {
        if (live) setLoading(false);
      }
    })();
    // A page the reader left is not allowed to overwrite the one they moved to.
    return function () { live = false; };
  }, [page]);

  // The segment narrows the page that is loaded; it never gates paging, so a
  // filtered page that looks sparse can still be followed by the next page.
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
              <div style={{ fontSize: 13, color: "var(--muted)" }}>Nothing in this category on this page{page < pages ? " — open the next page to keep looking." : "."}</div>
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
            {/* Paging is driven only by the total the gateway counted, never by
                the active filter. */}
            {pages > 1 && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14 }}>
                <button type="button" className="btn ghost" onClick={function () { setPage(function (p) { return Math.max(1, p - 1); }); }} disabled={loading || page <= 1}>Previous</button>
                <span style={{ flex: 1, textAlign: "center", fontSize: 13, color: "var(--muted)" }}>Page {page} of {pages}</span>
                <button type="button" className="btn ghost" onClick={function () { setPage(function (p) { return Math.min(pages, p + 1); }); }} disabled={loading || page >= pages}>Next</button>
              </div>
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
