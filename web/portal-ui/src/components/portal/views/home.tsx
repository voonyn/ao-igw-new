"use client";

import { useEffect, useMemo, useState, useSyncExternalStore } from "react";

import { Icon } from "../icons";
import { SecurityRing, KV, AppLogo, NotWired } from "../primitives";
import { useUser } from "../flow-context";
import { accountErrorFrom, appHue, appLetter, eventTime, type AccountErr } from "@/lib/format";
import { deriveHealth } from "@/lib/health";
import type { Actions, ActivityEventWire, ConnectedAppWire, Space } from "@/lib/types";

// Home dashboard, ported from portal/views-home.jsx.
//
// LIVE: the greeting (OIDC /userinfo + the viewer's own clock), the account-health
// checklist and its score, "needs attention", the sign-in chart and connected apps
// — all derived on the client from self-service account endpoints that already
// exist (/sessions, /activity, /connected-apps), one request each per page load.
// Each card degrades on its own: a failing endpoint leaves that card stating why,
// never the dashboard blank.
//
// NOT WIRED: the "Active space" card only. Org/space membership has no
// self-service API, so it keeps its fixture and its <NotWired/> marker.

// The largest page the account API serves. The chart reads one page and labels
// the span it actually covered, so a busy account simply gets a shorter window.
const ACTIVITY_PAGE = 100;
// The window the sign-in chart aims for. The single page it reads may cover less;
// the card then says so rather than claiming a window it never read.
const CHART_DAYS = 14;

const CHECK_ICON: Record<string, string> = { email: "mail", signins: "alert" };

// readCard performs one BFF read for one card: 200 hands the parsed body to
// `onOk`, anything else classifies through the shared mapper. It never throws, so
// one card's failure cannot reject the mount's Promise.allSettled or disturb a
// sibling card.
async function readCard(url: string, onOk: (data: unknown) => void, onErr: (e: AccountErr) => void) {
  try {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    const data = await res.json().catch(function () { return {}; });
    if (res.status === 200) onOk(data);
    else onErr(accountErrorFrom(res.status, (data as { error?: unknown }).error));
  } catch {
    onErr("error");
  }
}

// A card is loading exactly while it has neither data nor an error — every fetch
// path sets one or the other, so this needs no separate flag per card.
function pending(data: unknown, err: AccountErr) {
  return data === null && err === "";
}

// Local-midnight timestamp for an instant: the chart buckets the viewer's own
// calendar days, not UTC's. NaN for a value that does not parse.
function dayOf(iso: string): number {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return NaN;
  const d = new Date(t);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

// Step whole local days. Adding 86_400_000 drifts off midnight across a DST
// change; setDate does not.
function addDays(ms: number, n: number): number {
  const d = new Date(ms);
  d.setDate(d.getDate() + n);
  return d.getTime();
}

// buildChart buckets the caller's own sign-in events by local calendar day.
//
// The feed carries every audit action, not just sign-ins, so one page can reach
// back fewer than CHART_DAYS days. The chart therefore starts at the oldest event
// actually read: a bar for a day no data covered would be a fabricated zero,
// whereas a day inside the covered span with no sign-ins is real data and renders
// as a zero-height bar.
function buildChart(events: ActivityEventWire[]) {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const stamps = events.map(function (e) { return dayOf(e.createdAt); }).filter(function (n) { return !Number.isNaN(n); });
  let from = addDays(today, -(CHART_DAYS - 1));
  if (stamps.length) from = Math.max(from, Math.min(...stamps));
  if (from > today) from = today; // clock skew — never render a backwards span

  const days: { t: number; v: number }[] = [];
  for (let t = from; t <= today; t = addDays(t, 1)) days.push({ t, v: 0 });
  const at = new Map(days.map(function (d, i) { return [d.t, i] as const; }));
  for (const e of events) {
    if (e.action !== "login.succeeded" && e.action !== "login.failed") continue;
    const i = at.get(dayOf(e.createdAt));
    if (i !== undefined) days[i].v++;
  }
  return days;
}

export function HomeView({ spaceId, spaces, A, heroStyle }: { spaceId: string; spaces: Space[]; A: Actions; heroStyle: string }) {
  const u = useUser();
  const space = spaces.find((s) => s.id === spaceId) || spaces[0];
  const greet = useGreeting();

  // Per-card state: the data (null until it arrives) plus its own error status.
  const [sessionCount, setSessionCount] = useState<number | null>(null);
  const [sessionsErr, setSessionsErr] = useState<AccountErr>("");
  const [activity, setActivity] = useState<ActivityEventWire[] | null>(null);
  const [activityErr, setActivityErr] = useState<AccountErr>("");
  const [connApps, setConnApps] = useState<ConnectedAppWire[] | null>(null);
  const [appsErr, setAppsErr] = useState<AccountErr>("");

  // One fan-out on mount: three parallel reads, exactly one request per endpoint,
  // no polling and no refetch-on-focus. Each lands in its own card's state, so a
  // slow or failing endpoint never holds up the ones that already answered.
  // The whole body sits in an async IIFE so no setState runs synchronously in the
  // effect, matching the activity view. The setters are stable, hence deps [].
  useEffect(function () {
    void (async function () {
      await Promise.allSettled([
        readCard("/api/account/sessions", function (d) {
          const s = (d as { sessions?: unknown }).sessions;
          setSessionCount(Array.isArray(s) ? s.length : 0);
        }, setSessionsErr),
        // ponytail: one page at the service maximum, and the cursor is never
        // walked — so on a busy account the chart covers fewer than CHART_DAYS
        // days and labels the span it actually read. Walking the keyset to
        // guarantee 14 days is unbounded work on the landing page for a
        // decorative chart. Upgrade path when the short window bites: a
        // server-side GET /account/activity/summary returning per-day counts (D3).
        readCard("/api/account/activity?limit=" + ACTIVITY_PAGE, function (d) {
          const e = (d as { events?: unknown }).events;
          setActivity(Array.isArray(e) ? (e as ActivityEventWire[]) : []);
        }, setActivityErr),
        readCard("/api/account/connected-apps", function (d) {
          setConnApps(Array.isArray(d) ? (d as ConnectedAppWire[]) : []);
        }, setAppsErr),
      ]);
    })();
  }, []);

  // One derivation, shared with the Security view, so the ring cannot show two
  // different numbers for the same account. An input that failed stays null and
  // its check goes `unknown` — excluded from the score rather than counted
  // against a user who cannot act on it.
  const health = useMemo(function () {
    return deriveHealth({ emailVerified: u.emailVerified, activity, sessionCount });
  }, [u.emailVerified, activity, sessionCount]);

  const healthLoading = pending(activity, activityErr);
  const failing = health.checks.filter((c) => c.state === "warn");

  const chart = useMemo(function () { return activity ? buildChart(activity) : null; }, [activity]);
  const chartMax = chart ? Math.max(1, ...chart.map((d) => d.v)) : 1;

  // Sorted by updatedAt: AccountConnectedApp carries no last-used timestamp, so
  // "recently used" is not something this data can honestly claim (D6).
  const recentApps = useMemo(function () {
    if (!connApps) return [];
    return connApps.slice().sort(function (a, b) {
      return (Date.parse(b.updatedAt) || 0) - (Date.parse(a.updatedAt) || 0);
    }).slice(0, 4);
  }, [connApps]);

  const QUICK = [
    { id: "q1", icon: "lock", ttl: "Reset password", sub: "Change your password", nav: "security", label: "Manage" },
    { id: "q2", icon: "laptop", ttl: "Where you're signed in", sub: "Review active sessions", nav: "security", label: "Review" },
    { id: "q3", icon: "link", ttl: "Connected apps", sub: "Apps with access to your account", nav: "devices", label: "Manage" },
    { id: "q4", icon: "idcard", ttl: "Edit profile", sub: "Personal details", nav: "profile", label: "Update" },
  ];

  return (
    <div className="fade-in">
      {/* ---- HERO ---- */}
      <div className="hero">
        <div className="hero-inner">
          <div className="hero-text">
            <div className="eyebrow"><Icon name="sparkle" size={14} sw={2.2} />{space.kind === "WIAM" ? "Workforce identity" : "Your AlphaOmega ID"}</div>
            <h1>{greet}, {u.firstName}.</h1>
            <div className="hero-sub">
              {heroStyle === "minimal"
                ? "Everything about your account in one place — security, sign-in, apps and devices."
                : "Your identity is protected and unified across " + spaces.length + " spaces. Here’s a quick look at your account health."}
            </div>
            <div className="hero-actions">
              <button type="button" className="btn lg white-hero" onClick={() => A.nav("security")}>
                <Icon name="shield" size={16} sw={2} />Review security
              </button>
              <button type="button" className="btn lg on-hero" onClick={() => A.nav("devices")}>
                <Icon name="link" size={16} sw={2} />Connected apps
              </button>
            </div>
          </div>
          {heroStyle !== "minimal" && <SecurityRing score={health.score} size={138} stroke={12} light={true} />}
        </div>
      </div>

      {/* ---- QUICK ACTIONS ---- */}
      <div className="quick-grid stagger">
        {QUICK.map((q) => (
          <button key={q.id} type="button" className="quick" onClick={() => A.nav(q.nav)}>
            <span className="qicon"><Icon name={q.icon} size={19} sw={2} /></span>
            <div>
              <div className="qttl">{q.ttl}</div>
              <div className="qsub">{q.sub}</div>
            </div>
            <span className="qarrow">{q.label}<Icon name="arrowR" size={13} sw={2.2} /></span>
          </button>
        ))}
      </div>

      {/* ---- MAIN GRID ---- */}
      <div className="col-2">
        {/* Account health — LIVE, derived by lib/health.ts */}
        <div className="card">
          <div className="card-head">
            <div>
              <span className="card-title">Account health</span>
              <div className="card-sub">
                {healthLoading ? "Checking your account…"
                  : health.scored === 0 ? "Couldn’t check your account right now"
                    : health.passing + " of " + health.scored + " check" + (health.scored === 1 ? "" : "s") + " passing"}
              </div>
            </div>
            <span className="spacer"></span>
            <button type="button" className="btn sm ghost" onClick={() => A.nav("security")}>Open<Icon name="arrowR" size={13} /></button>
          </div>
          <div className="card-pad" style={{ paddingTop: 12 }}>
            {health.checks.map((it) => (
              <div key={it.id} className="check-item">
                <span className={"ci-dot " + it.state}>
                  <Icon name={it.state === "good" ? "check" : it.state === "warn" ? "alert" : "clock"} size={12} sw={it.state === "good" ? 3 : 2.4} />
                </span>
                <div className="ci-main">
                  <div className="ci-ttl">{it.label}</div>
                  <div className="ci-sub">{healthLoading && it.state === "unknown" ? "Checking…" : it.detail}</div>
                </div>
                {/* An unknown check is neither passing nor failing: it says so, and
                    offers no fix, because there is nothing the user can do. */}
                {it.state === "warn"
                  ? <button type="button" className="btn sm ghost" onClick={() => A.nav(it.nav)}>Fix</button>
                  : it.state === "good"
                    ? <span className="badge green"><span className="bdot"></span>OK</span>
                    : <span className="badge gray">{healthLoading ? "Checking" : "Unavailable"}</span>}
              </div>
            ))}
            {/* Informational, never scored — "how many sessions is too many" is not
                something this data can answer. */}
            <div className="check-item">
              <span className="ci-dot unknown"><Icon name="laptop" size={12} sw={2.4} /></span>
              <div className="ci-main">
                <div className="ci-ttl">Active sessions</div>
                <div className="ci-sub">
                  {pending(sessionCount, sessionsErr) ? "Checking…"
                    : health.sessions.known
                      ? health.sessions.count + " device" + (health.sessions.count === 1 ? "" : "s") + " signed in"
                      : "Couldn’t check where you’re signed in"}
                </div>
              </div>
              <button type="button" className="btn sm ghost" onClick={() => A.nav("security")}>Review</button>
            </div>
          </div>
        </div>

        {/* Right column */}
        <div className="stack">
          {/* Identity context — NOT WIRED: no self-service API for org/space membership */}
          <div className="card card-pad">
            <span className="sect-title"><Icon name="globe" size={13} sw={2} />Active space<span style={{ marginLeft: "auto" }}><NotWired /></span></span>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 4 }}>
              <span className="org-tile" style={{ width: 40, height: 40, borderRadius: 11, background: space.accent, color: "#fff", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 15, flexShrink: 0 }}>{space.tile}</span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: 14 }}>{space.name}</div>
                <div style={{ fontSize: 12.5, color: "var(--muted)" }}>{space.desc}</div>
              </div>
            </div>
            <div style={{ marginTop: 14 }}>
              <KV k="Type" v={<span className="badge accent">{space.type}</span>} />
              <KV k="Member since" v={u.memberSince} />
            </div>
          </div>

          {/* Needs attention — LIVE: exactly the failing health checks */}
          <div className="card card-pad">
            <span className="sect-title"><Icon name="clock" size={13} sw={2} />Needs attention</span>
            {healthLoading && <div style={{ fontSize: 13, color: "var(--muted)", paddingTop: 6 }}>Checking your account…</div>}
            {!healthLoading && failing.length === 0 && health.scored > 0 && (
              <div className="lrow" style={{ paddingTop: 6, borderBottom: "none" }}>
                <span className="licon good"><Icon name="check" size={18} sw={2.6} /></span>
                <div className="lmain">
                  <div className="lttl">Nothing needs your attention</div>
                  <div className="lsub">Every check we can run is passing.</div>
                </div>
              </div>
            )}
            {!healthLoading && failing.length === 0 && health.scored === 0 && (
              <div style={{ fontSize: 13, color: "var(--muted)", paddingTop: 6 }}>
                We couldn’t check your account right now. Try again in a moment.
              </div>
            )}
            {!healthLoading && failing.map((c) => (
              <div key={c.id} className="lrow" style={{ paddingTop: 6 }}>
                <span className="licon accent"><Icon name={CHECK_ICON[c.id] || "alert"} size={18} sw={2} /></span>
                <div className="lmain">
                  <div className="lttl">{c.label}</div>
                  <div className="lsub">{c.detail}</div>
                </div>
                <span className="lend">
                  <button type="button" className="btn sm ghost" onClick={() => A.nav(c.nav)}>Fix<Icon name="arrowR" size={13} sw={2.2} /></button>
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ---- Sign-in activity + apps ---- */}
      <div className="col-2">
        {/* Sign-in chart — LIVE via /api/account/activity */}
        <div className="card">
          <div className="card-head">
            <div>
              <span className="card-title">Sign-in activity</span>
              <div className="card-sub">
                {chart
                  ? "Last " + chart.length + " day" + (chart.length === 1 ? "" : "s") + " of your recorded sign-ins"
                  : "Your recorded sign-ins, day by day"}
              </div>
            </div>
            <span className="spacer"></span>
            <button type="button" className="btn sm ghost" onClick={() => A.nav("activity")}>View all</button>
          </div>
          <div className="card-pad" style={{ paddingTop: 16 }}>
            {activityErr && <CardError err={activityErr} what="activity" unavailable="Activity history isn’t available on this server." />}
            {pending(activity, activityErr) && <div style={{ fontSize: 13, color: "var(--muted)" }}>Loading sign-in activity…</div>}
            {chart && chart.length > 0 && (
              <div className="bars">
                {chart.map((d) => (
                  <div key={d.t} className="bar">
                    <div className="fill" style={{ height: Math.round((d.v / chartMax) * 100) + "%" }}></div>
                    <div className="tip">
                      {new Date(d.t).toLocaleDateString(undefined, { month: "short", day: "numeric" })} · {d.v} sign-in{d.v === 1 ? "" : "s"}
                    </div>
                  </div>
                ))}
              </div>
            )}
            {chart && chart.length > 0 && chart.every((d) => d.v === 0) && (
              <div style={{ fontSize: 13, color: "var(--muted)", marginTop: 10 }}>No sign-ins recorded in this window yet.</div>
            )}
          </div>
        </div>

        {/* Connected apps — LIVE via /api/account/connected-apps */}
        <div className="card">
          <div className="card-head">
            <span className="card-title">Connected apps</span>
            <span className="spacer"></span>
            <button type="button" className="btn sm ghost" onClick={() => A.nav("devices")}>Manage</button>
          </div>
          <div className="card-pad" style={{ paddingTop: 12 }}>
            {appsErr && <CardError err={appsErr} what="connected apps" unavailable="Connected-app management isn’t available on this server." />}
            {pending(connApps, appsErr) && <div style={{ fontSize: 13, color: "var(--muted)" }}>Loading connected apps…</div>}
            {connApps && connApps.length === 0 && (
              <div style={{ fontSize: 13, color: "var(--muted)" }}>
                No connected apps yet. Services you sign in to with AlphaOmega will appear here.
              </div>
            )}
            {recentApps.map((a) => (
              <div key={a.clientId} className="lrow" style={{ padding: "10px 0" }} onClick={() => A.nav("devices")}>
                <AppLogo letter={appLetter(a.name)} hue={appHue(a.clientId)} size={36} />
                <div className="lmain">
                  <div className="lttl">{a.name}</div>
                  <div className="lsub">Last updated {eventTime(a.updatedAt)}</div>
                </div>
                <span className="lend"><Icon name="arrowR" size={15} sw={2} style={{ color: "var(--muted-2)" }} /></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// CardError renders one card's own failure. Scoped per card on purpose: a 401 or a
// rate limit on one endpoint says so where it happened and leaves every other card
// showing its live data.
function CardError({ err, what, unavailable }: { err: AccountErr; what: string; unavailable: string }) {
  if (!err) return null;
  return (
    <div style={{ marginBottom: 10, fontSize: 13, color: err === "reauth" ? "var(--error)" : err === "unavailable" ? "var(--muted)" : "var(--warn)" }}>
      {err === "reauth" && <>Your session is no longer valid. <a href="/auth/login" style={{ color: "var(--accent)", fontWeight: 600 }}>Sign in again</a></>}
      {err === "rate" && "Too many requests. Please wait a minute and try again."}
      {err === "unavailable" && unavailable}
      {err === "error" && "Could not load your " + what + ". Please try again in a moment."}
    </div>
  );
}

// The greeting reads the viewer's own clock, which the server does not have — it
// renders this component too, and greeting from its hour is how `const hour = 8`
// happened. useSyncExternalStore serves the server a neutral greeting and the
// client the real one, with no hydration mismatch and no setState in an effect.
// The store never notifies: the hour is read per render, which is plenty for a
// greeting nobody watches tick over.
const NEVER_CHANGES = function () { return function () {}; };
function localGreeting(): string {
  const hour = new Date().getHours();
  return hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
}
function serverGreeting(): string { return "Hello"; }

function useGreeting(): string {
  return useSyncExternalStore(NEVER_CHANGES, localGreeting, serverGreeting);
}
