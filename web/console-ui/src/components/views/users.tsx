"use client";

import { useEffect, useId, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Icon } from "@/components/console/icons";
import { Avatar, Btn, confirmAction, Field, KV, MonoChip, Seg, SelectInput, Ts, UserStateBadge, VerifiedBadge, ViewNotice } from "@/components/console/primitives";
import { DataTable, type BulkAction, type Column } from "@/components/console/data-table";
import { useTabParam } from "@/components/console/detail-route";
import { AuditLog } from "@/components/views/audit";
import { sessionColumns, terminateBulk } from "@/components/views/sessions";
import { EntityHeader, FullPage, ReadField, SectionCard, TabPanel, Tabs } from "@/components/console/overlays";
import { useConsole, usePagedList, usePending, type Actions } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { authPolicyApi, canManageTenant, canWriteAnyOrg, canWriteOrg, pages, passkeysApi, sessionsApi, userMemberships, usersApi, type AuthPolicy, type Me, type Passkey, type UserMemberships } from "@/lib/console-api";
import { LABELS } from "@/lib/data";
import { fmtTs, orgName, orNever, userDisplay } from "@/lib/helpers";
import { passwordViolation, policyRules } from "@/lib/password-policy";
import type { User } from "@/lib/types";

// Org roles that may write users (mirrors the gateway's loadUserForWrite gate).
const USER_WRITE_ROLES = ["ORG_OWNER", "ORG_USER_MANAGER"];

// Signing a person out everywhere is NOT a user write: it ends login sessions,
// which are held across the whole tenant, and the gateway gates
// DELETE /users/:id/sessions on a tenant manager
// (internal/session/admin_service.go: authorize). An org manager who was offered
// the button only received a 403.

export function UserDetailPage({
  user,
  A,
  canWrite,
  onClose,
  onChanged,
}: {
  user: User;
  A: Actions;
  canWrite: boolean;
  onClose: () => void;
  /** Re-read this record from the server after a write (EH-6). */
  onChanged?: () => Promise<void>;
}) {
  const { accessibleOrgs, digitalIdentity, me } = useConsole();
  const h = user.human;
  // The investigation tabs are the point of this screen: what can this person
  // reach, what are they signed into, and what have they done — three questions
  // that used to mean cross-referencing three screens by uuid, by eye.
  const TABS = (h ? ["Profile", "Security"] : ["Details"]).concat(["Sessions", "Permissions", "Audit", "Record"]);
  const [tab, setTab] = useTabParam(TABS);
  const [firstName, setFirstName] = useState(h?.firstName ?? "");
  const [lastName, setLastName] = useState(h?.lastName ?? "");
  const [displayName, setDisplayName] = useState(h?.displayName ?? "");
  const [lang, setLang] = useState(h?.lang ?? "en");
  const [busy, runGuarded] = usePending();

  // Runs a write, surfaces success/failure honestly, and refreshes the console.
  async function run(fn: () => Promise<unknown>, ok: string, okIcon?: string, close?: boolean) {
    const done = await runGuarded(fn, {
      ok,
      icon: okIcon,
      after: async () => {
        await A.reload();
        if (!close && onChanged) await onChanged();
      },
    });
    if (done && close) onClose();
  }

  function saveProfile() {
    void run(
      () => usersApi.update(user.id, { firstName, lastName, displayName, lang, phone: h?.phone ?? "" }),
      "Profile saved",
    );
  }

  async function signOutEverywhere() {
    const ok = await confirmAction({
      title: `Sign ${userDisplay(user)} out everywhere?`,
      body: "Every login session ends and every token grant is revoked, refresh tokens included — so nothing can be renewed and they must sign in again on every device. Access tokens already issued stay valid at the relying party until they expire.",
      confirmLabel: "Sign out everywhere",
      destructive: true,
    });
    if (!ok) return;
    await run(() => sessionsApi.revokeForUser(user.id), "Signed out " + userDisplay(user) + " everywhere", "logout");
  }

  async function deactivate() {
    const ok = await confirmAction({
      title: `Deactivate ${userDisplay(user)}?`,
      body: "The account can no longer sign in. Every existing session is signed out and every issued token is revoked immediately; an access token already in an app’s hands stops working when it expires. Reactivating restores access, but they will have to sign in again.",
      confirmLabel: "Deactivate",
      destructive: true,
    });
    if (!ok) return;
    await run(() => usersApi.deactivate(user.id), "Deactivated " + userDisplay(user), "ban");
  }

  async function remove() {
    const ok = await confirmAction({
      title: `Delete ${userDisplay(user)}?`,
      body: "The account is soft-deleted: it can no longer sign in, every existing session is signed out, every issued token is revoked, its memberships stop granting anything, and it disappears from this console. The record is retained in the database, but nothing here will bring it back.",
      confirmLabel: "Delete user",
      destructive: true,
    });
    if (!ok) return;
    await run(() => usersApi.remove(user.id), "Deleted " + userDisplay(user), "ban", true);
  }

  async function resetMfa() {
    const ok = await confirmAction({
      title: `Reset two-factor for ${userDisplay(user)}?`,
      body: "Their authenticator, recovery codes, and every registered passkey are removed immediately. They sign in with a password alone until they re-enrol — which weakens their account until they do.",
      confirmLabel: "Reset two-factor",
      destructive: true,
    });
    if (!ok) return;
    await run(() => usersApi.resetMfa(user.id), "Two-factor reset for " + userDisplay(user), "key");
  }

  // Access actions are identical for human & machine; shared danger card.
  const accessCard = canWrite && user.state !== 3 && (
    <SectionCard danger title="Access" desc="Sign out, unlock, deactivate, or delete this account. These actions take effect immediately.">
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {canManageTenant(me) && (
          <Btn className="btn danger-ghost" pending={busy} onClick={signOutEverywhere}>
            <Icon name="logout" size={15} />
            Sign out everywhere
          </Btn>
        )}
        {user.state === 4 && (
          <Btn className="btn ghost" pending={busy} onClick={() => void run(() => usersApi.unlock(user.id), "Unlocked " + userDisplay(user), "key")}>
            <Icon name="key" size={15} />
            Unlock
          </Btn>
        )}
        {user.state === 2 ? (
          <Btn className="btn ghost" pending={busy} onClick={() => void run(() => usersApi.activate(user.id), "Reactivated " + userDisplay(user))}>
            <Icon name="refresh" size={15} />
            Reactivate
          </Btn>
        ) : (
          <Btn className="btn danger-ghost" pending={busy} onClick={deactivate}>
            <Icon name="ban" size={15} />
            Deactivate
          </Btn>
        )}
        <Btn className="btn danger-ghost" pending={busy} onClick={remove}>
          <Icon name="ban" size={15} />
          Delete
        </Btn>
      </div>
    </SectionCard>
  );

  return (
    <FullPage backLabel="Users" crumb={userDisplay(user)} onBack={onClose}>
      <EntityHeader
        tile={
          user.userType === 2 ? (
            <span className="entity-tile" style={{ background: "var(--field)", border: "1px solid var(--border)", color: "var(--muted)" }}>
              <Icon name="terminal" size={24} />
            </span>
          ) : (
            <Avatar name={userDisplay(user)} size={56} fontSize={20} />
          )
        }
        title={userDisplay(user)}
        meta={
          <>
            <UserStateBadge state={user.state} />
            {user.userType === 2 ? (
              <span className="badge gray">
                <Icon name="terminal" size={11} sw={2.2} />
                Machine
              </span>
            ) : (
              <span className="badge accent">Human</span>
            )}
            <span>{orgName(accessibleOrgs, user.orgId)}</span>
            <span>Username</span>
            <MonoChip value={user.username} toast={A.toast} />
          </>
        }
      />

      {user.state === 5 && (
        <div className="proto-banner" style={{ marginBottom: 18 }}>
          <Icon name="clock" size={16} sw={2} style={{ color: "var(--warn)", flexShrink: 0, marginTop: 1 }} />
          <div>
            <b>Initial state.</b> This user has not completed first sign-in. Email verification and password setup are outstanding.
          </div>
        </div>
      )}

      <Tabs tabs={TABS} value={tab} onChange={setTab} group="user" />

      {tab === "Sessions" && (
        <TabPanel tab="Sessions" group="user">
          <UserSessionsTab user={user} me={me} />
        </TabPanel>
      )}

      {tab === "Permissions" && (
        <TabPanel tab="Permissions" group="user">
          <UserPermissionsTab user={user} />
        </TabPanel>
      )}

      {tab === "Audit" && (
        <TabPanel tab="Audit" group="user">
          <UserAuditTab user={user} me={me} toast={A.toast} />
        </TabPanel>
      )}

      {h && tab === "Profile" && (
        <div>
          <SectionCard title="Basic Information" desc="Core profile fields shown to the user and mapped into issued tokens.">
            <div className="form-grid">
              <div>
                <Field label="First name">
                  <input className="text-input" value={firstName} disabled={!canWrite} onChange={(e) => setFirstName(e.target.value)} />
                </Field>
              </div>
              <div>
                <Field label="Last name">
                  <input className="text-input" value={lastName} disabled={!canWrite} onChange={(e) => setLastName(e.target.value)} />
                </Field>
              </div>
              <div>
                <Field label="Display name">
                  <input className="text-input" value={displayName} disabled={!canWrite} onChange={(e) => setDisplayName(e.target.value)} />
                </Field>
              </div>
              <div>
                <Field label="Preferred language">
                  <SelectInput value={lang} options={["en", "th", "de", "sv", "ja", "fr"]} onChange={setLang} />
                </Field>
              </div>
            </div>
            {canWrite && (
              <Btn className="btn sm primary" style={{ marginTop: 12 }} pending={busy} onClick={saveProfile}>
                Save profile
              </Btn>
            )}
          </SectionCard>

          <SectionCard title="Contact" desc="Email and phone identifiers, with their verification status.">
            <KV
              k={
                <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
                  <Icon name="mail" size={14} />
                  Email
                </span>
              }
              v={
                <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{h.email || "—"}</span>
                  {h.email && <VerifiedBadge on={h.emailVerified} />}
                </span>
              }
            />
            <KV
              k={
                <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
                  <Icon name="phone" size={14} />
                  Phone
                </span>
              }
              v={
                <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{h.phone || "—"}</span>
                  {h.phone && <VerifiedBadge on={h.phoneVerified} />}
                </span>
              }
            />
          </SectionCard>

          {/* Read-only, and rendered only when this deployment runs a Scan
              Verifier. The gate is the gateway's own capability, not the
              presence of the field: an absent field answers "the API left it
              out", which is a different question. "Not enrolled" is how an
              operator finds the people an outage left unmirrored. */}
          {digitalIdentity && (
            <SectionCard title="Digital identity" desc="Whether this person is registered with the Scan Verifier. It is written when the account is created and cannot be edited here.">
              <KV
                k="Enrolment"
                v={
                  h.diEnrolled ? (
                    <span className="badge accent">Enrolled</span>
                  ) : (
                    <span className="badge gray">Not enrolled</span>
                  )
                }
              />
            </SectionCard>
          )}
        </div>
      )}

      {h && tab === "Security" && (
        <div>
          <SectionCard title="Password" desc="Credential status for this user. Reset links let the user set a new password themselves.">
            <KV k="Last changed" v={<Ts value={h.pwdChangedAt} empty="Never" />} />
            {canWrite && h.email && (
              <Btn
                className="btn sm ghost"
                style={{ marginTop: 8 }}
                pending={busy}
                onClick={() => void run(() => usersApi.passwordReset(user.id), "Reset link sent to " + h.email, "send")}
              >
                <Icon name="send" size={13} />
                Send reset link
              </Btn>
            )}
          </SectionCard>
          <SectionCard title="Two-factor authentication" desc="Two-factor status — an authenticator app (TOTP) or a passkey. Resetting removes all second factors (the authenticator, its recovery codes, and every passkey), so the user re-enrolls on their next sign-in — use it for device-lost recovery.">
            <KV
              k="Two-factor"
              v={
                user.mfaEnabled ? (
                  <span className="badge accent">Enabled</span>
                ) : (
                  <span className="badge gray">Disabled</span>
                )
              }
            />
            {canWrite && user.mfaEnabled && (
              <Btn className="btn sm danger-ghost" style={{ marginTop: 8 }} pending={busy} onClick={resetMfa}>
                <Icon name="ban" size={13} />
                Reset two-factor
              </Btn>
            )}
          </SectionCard>
          {/* Rendered for every administrator, the way the two cards above are.
              The gateway gates the list on the read role — the same role that
              answered the account record beside it — and gates the revoke alone
              on the write role, so `canWrite` gates the row button and not the
              card. Revoking one device is the narrow answer to "I lost my
              laptop" — every other factor that person holds survives it, which
              is what tells it apart from the reset above. */}
          <UserPasskeysCard user={user} canWrite={canWrite} onChanged={onChanged} />
          {accessCard}
        </div>
      )}

      {!h && tab === "Details" && (
        <div>
          <SectionCard title="Service account" desc="Machine identity used for server-to-server access. Tokens are issued programmatically.">
            <KV
              k="Type"
              v={
                <span className="badge gray">
                  <Icon name="terminal" size={11} sw={2.2} />
                  Machine
                </span>
              }
            />
            <KV k="Last token issued" v={<Ts value={user.lastAuth} empty="Never" />} />
          </SectionCard>
          {accessCard}
        </div>
      )}

      {tab === "Record" && (
        <SectionCard title="Record" desc="Immutable identifiers and audit timestamps for this account.">
          <ReadField label="User ID" value={user.id} mono toast={A.toast} />
          <KV k="Created" v={<Ts value={user.created} />} />
          <KV k="Last authentication" v={<Ts value={user.lastAuth} empty="Never" />} />
        </SectionCard>
      )}
    </FullPage>
  );
}

/**
 * The passkeys this person holds, and the revoke for one of them.
 *
 * The console never registers a passkey: a factor belongs to whoever holds the
 * device, so the ceremony runs in the portal under that person's own token. This
 * card reads and revokes, and the gateway mounts no third route.
 *
 * The list is bounded — ten per person — so it answers whole and carries no
 * pager, the way the memberships read does.
 *
 * Every administrator reads the list, so the card renders for all of them,
 * empty state included. `canWrite` gates the revoke button alone, because the
 * gateway gates the revoke alone on the write role.
 */
function UserPasskeysCard({ user, canWrite, onChanged }: { user: User; canWrite: boolean; onChanged?: () => Promise<void> }) {
  const { A, dataVersion } = useConsole();
  const [state, setState] = useState<{ phase: "loading" } | { phase: "ready"; rows: Passkey[] } | { phase: "error"; why: string }>({
    phase: "loading",
  });
  const [busy, runGuarded] = usePending();
  // Bumped by a revoke, so the list re-reads without waiting for the console-wide
  // refresh the parent also triggers.
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let cancelled = false;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setState({ phase: "loading" });
    passkeysApi
      .list(user.id)
      .then((out) => {
        if (cancelled) return;
        setState(
          out.ok
            ? { phase: "ready", rows: out.data }
            : { phase: "error", why: out.reason === "forbidden" ? "Reading this user's passkeys requires a role you don't hold." : "This user is outside your access." }
        );
      })
      .catch((e: unknown) => {
        if (!cancelled) setState({ phase: "error", why: e instanceof Error ? e.message : "Request failed" });
      });
    return () => {
      cancelled = true;
    };
  }, [user.id, dataVersion, version]);

  async function revoke(row: Passkey) {
    const ok = await confirmAction({
      // The device is named in the title. Two passkeys may share a name, so the
      // body carries when it was added — that is what tells them apart.
      title: `Revoke “${row.name}” for ${userDisplay(user)}?`,
      body: `This passkey stops signing them in immediately. It was added ${fmtTs(row.createdAt)}. Every other second factor they hold — their authenticator and any other passkey — is untouched. They cannot undo this; the device must be registered again from their account.`,
      confirmLabel: "Revoke passkey",
      destructive: true,
    });
    if (!ok) return;
    await runGuarded(() => passkeysApi.revoke(user.id, row.id), {
      ok: `Revoked “${row.name}”`,
      icon: "key",
      after: async () => {
        setVersion((v) => v + 1);
        await A.reload();
        // The two-factor badge above turns on the passkeys and the authenticator
        // together, so revoking the last factor changes the record this page
        // renders.
        if (onChanged) await onChanged();
      },
    });
  }

  return (
    <SectionCard title="Passkeys" desc="Devices this person signs in with instead of a code. Revoking one takes that device out of service and leaves every other second factor in place — use it when a device is lost. Passkeys are registered by the user, never from here.">
      {state.phase === "loading" && <div style={{ fontSize: 13, color: "var(--muted)" }}>Loading passkeys…</div>}
      {state.phase === "error" && <div style={{ fontSize: 13, color: "var(--muted)" }}>{state.why}</div>}
      {state.phase === "ready" && state.rows.length === 0 && (
        <div style={{ fontSize: 13, color: "var(--muted)" }}>This account has no passkeys.</div>
      )}
      {state.phase === "ready" &&
        state.rows.map((row) => (
          <KV
            key={row.id}
            k={
              <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
                <Icon name="fingerprint" size={14} />
                {row.name}
              </span>
            }
            v={
              <span style={{ display: "inline-flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <span style={{ fontSize: 12, color: "var(--muted)" }}>
                  Added <Ts value={row.createdAt} /> · Last used <Ts value={row.lastUsedAt} empty="Never" />
                </span>
                {canWrite && (
                  <Btn className="btn sm danger-ghost" pending={busy} onClick={() => void revoke(row)}>
                    <Icon name="ban" size={13} />
                    Revoke
                  </Btn>
                )}
              </span>
            }
          />
        ))}
    </SectionCard>
  );
}

/**
 * The user's login sessions — that user's, read server-side, including
 * terminated ones.
 *
 * It is the tenant-wide Sessions read narrowed by `userId`, not the tenant-wide
 * collection filtered in the client: the same reader, the same page contract,
 * the same per-session actions. Before the subject filter existed the only way
 * to answer this was to scroll the Sessions view looking for a uuid.
 */
function UserSessionsTab({ user, me }: { user: User; me: Me }) {
  const list = usePagedList(pages.sessions, "sessions", { userId: user.id, orgId: null });
  return (
    <SectionCard title="Login sessions" desc="Every SSO session for this account, active and signed out. Revoking a session revokes its token grants — refresh tokens included — and deletes the record.">
      <DataTable
        id="user-sessions"
        list={list}
        columns={sessionColumns().filter((c) => c.key !== "user")}
        rowKey={(s) => s.id}
        noun="session"
        empty="This account has no login sessions."
        bulk={[terminateBulk(me)]}
      />
    </SectionCard>
  );
}

/**
 * What this user can actually do: their tenant roles and every organization
 * membership with its roles.
 *
 * `UserDTO` carries no roles at all, and the two membership reads existed only
 * behind the caller's OWN gate — so this is the one genuinely new endpoint the
 * change adds. Both halves come back whole: one person's memberships are bounded
 * by the organizations they belong to.
 */
function UserPermissionsTab({ user }: { user: User }) {
  const { accessibleOrgs, dataVersion } = useConsole();
  const [state, setState] = useState<{ phase: "loading" } | { phase: "ready"; data: UserMemberships } | { phase: "error"; why: string }>({
    phase: "loading",
  });

  useEffect(() => {
    let cancelled = false;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setState({ phase: "loading" });
    userMemberships(user.id)
      .then((out) => {
        if (cancelled) return;
        setState(
          out.ok
            ? { phase: "ready", data: out.data }
            : { phase: "error", why: out.reason === "forbidden" ? "Reading this user's memberships requires a role you don't hold." : "This user is outside your access." }
        );
      })
      .catch((e: unknown) => {
        if (!cancelled) setState({ phase: "error", why: e instanceof Error ? e.message : "Request failed" });
      });
    return () => {
      cancelled = true;
    };
  }, [user.id, dataVersion]);

  if (state.phase === "loading") return <SectionCard title="Permissions" desc="Loading…">{null}</SectionCard>;
  if (state.phase === "error")
    return <ViewNotice title="Couldn’t load this user's permissions." body={state.why} />;

  const { tenantMemberships, orgMemberships } = state.data;
  return (
    <div>
      <SectionCard title="Tenant roles" desc="IAM roles held at tenant level. These grant authority across every organization.">
        {tenantMemberships.length === 0 ? (
          <div style={{ fontSize: 13, color: "var(--muted)" }}>No tenant-level roles — this account is not a tenant administrator.</div>
        ) : (
          tenantMemberships.map((m) => (
            <KV
              key={m.userId}
              k="IAM roles"
              v={
                <span className="chip-row">
                  {m.roles.map((r) => (
                    <span key={r} className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                      {r}
                    </span>
                  ))}
                </span>
              }
            />
          ))
        )}
      </SectionCard>
      <SectionCard title="Organization memberships" desc="Each organization this account holds a role grant in. Only organizations you can read are listed.">
        {orgMemberships.length === 0 ? (
          <div style={{ fontSize: 13, color: "var(--muted)" }}>No organization memberships in your scope.</div>
        ) : (
          orgMemberships.map((m) => (
            <KV
              key={m.orgId}
              k={orgName(accessibleOrgs, m.orgId)}
              v={
                <span className="chip-row">
                  {m.roles.map((r) => (
                    <span key={r} className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                      {r}
                    </span>
                  ))}
                </span>
              }
            />
          ))
        )}
      </SectionCard>
    </div>
  );
}

/**
 * What this user did, and what was done to them.
 *
 * Two reads rather than one, because `audit.repository.List` ANDs `actor_id` and
 * `entity_id` — "by them OR about them" is not expressible in a single query,
 * and it is the more useful distinction for an operator anyway.
 */
function UserAuditTab({ user, me, toast }: { user: User; me: Me; toast: Actions["toast"] }) {
  const [side, setSide] = useState("Performed by them");

  // The audit read is tenant-manager-gated at both the route and the service.
  // The tab still renders and states the role rather than disappearing: a
  // console that differs by role without saying so reads as a missing feature.
  if (!me.isTenantManager) {
    return (
      <ViewNotice
        title="You can't view the audit log."
        body="Reading audit events requires an tenant-manager role (IAM_OWNER or IAM_ADMIN). Organization-scoped audit is not offered."
      />
    );
  }

  return (
    <div>
      <div className="filter-row" style={{ marginBottom: 14 }}>
        <Seg options={["Performed by them", "Performed on them"]} value={side} onChange={setSide} />
      </div>
      <AuditLog
        // Remount on switch: the two are different reads, and carrying one's
        // accumulated pages into the other would mix them.
        key={side}
        toast={toast}
        title={null}
        fixed={side === "Performed by them" ? { actor: user.id } : { entityId: user.id }}
      />
    </div>
  );
}

export function CreateUserPage({ onClose }: { onClose: () => void }) {
  const orgFieldId = useId();
  const { me, accessibleOrgs } = useConsole();
  // Bounded by the caller's own memberships and already loaded — no list read.
  const orgs = accessibleOrgs.filter((o) => canWriteOrg(me, o.id, USER_WRITE_ROLES));
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgNameSel, setOrgNameSel] = useState("");
  const [type, setType] = useState("Human");
  const [busy, run] = usePending();
  const isHuman = type === "Human";

  // The rules the server will apply, read from the tenant's resolved policy so
  // the form can't promise a validation it doesn't perform. A refused read
  // (org-scoped caller) leaves `policy` null and the server stays the only gate.
  const [policy, setPolicy] = useState<AuthPolicy | null>(null);
  useEffect(() => {
    authPolicyApi
      .get()
      .then((out) => setPolicy(out.ok ? out.data : null))
      .catch(() => setPolicy(null));
  }, []);

  const org = orgs.find((o) => o.name === orgNameSel) ?? orgs[0];
  const pwError = password ? passwordViolation(password, policy) : null;
  const rules = policyRules(policy);
  const valid = isHuman && !!username.trim() && /.+@.+\..+/.test(email) && !!password && !pwError && orgs.length > 0;

  async function create() {
    if (!valid || !org) return;
    const done = await run(
      () =>
        usersApi.create({
          orgId: org.id,
          username: username.trim(),
          email: email.trim(),
          firstName: "",
          lastName: "",
          displayName: username.trim(),
          lang: "en",
          password,
          emailVerified: false,
        }),
      { ok: "Created user " + username.trim() }
    );
    if (done) onClose();
  }

  return (
    <FullPage backLabel="Users" crumb="New user" onBack={onClose}>
      <h1 className="entity-title" style={{ margin: "8px 0 4px" }}>
        New user
      </h1>
      <div className="entity-meta" style={{ marginBottom: 22 }}>
        Human users receive an email invite; machine users are active immediately.
      </div>
      <SectionCard title="Basic Information" desc="Choose the identity type, then give it a username and home organization.">
        <div>
          <span className="field-label">Type</span>
          <Seg options={["Human", "Machine"]} value={type} onChange={setType} label="Identity type" />
          {!isHuman && (
            <div style={{ marginTop: 8, fontSize: 12.5, color: "var(--warn)", display: "flex", alignItems: "center", gap: 6 }}>
              <Icon name="alert" size={13} sw={2.2} />
              Service accounts aren&apos;t creatable through the admin API yet.
            </div>
          )}
        </div>
        <div>
          <Field label={<>Username <span style={{ color: "var(--muted-2)" }}>(unique per tenant)</span></>}>
            <input className="text-input" placeholder="jane.doe" value={username} disabled={!isHuman} onChange={(e) => setUsername(e.target.value)} />
          </Field>
        </div>
        {isHuman && (
          <>
            <div>
              <Field label="Email">
                <input className="text-input" placeholder="jane.doe@acme.com" value={email} onChange={(e) => setEmail(e.target.value)} />
              </Field>
            </div>
            <div>
              <Field label="Initial password">
                <input
                  className="text-input"
                  type="password"
                  placeholder={policy && policy.pwMinLength > 0 ? `At least ${policy.pwMinLength} characters` : "Initial password"}
                  value={password}
                  aria-invalid={!!pwError}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </Field>
              {pwError ? (
                <div style={{ marginTop: 6, fontSize: 12.5, color: "var(--error)", display: "flex", alignItems: "center", gap: 6 }}>
                  <Icon name="alert" size={13} sw={2.2} />
                  {pwError}
                </div>
              ) : null}
              {rules.length > 0 ? (
                <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: "var(--muted)", lineHeight: 1.7 }}>
                  {rules.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              ) : (
                <div style={{ marginTop: 6, fontSize: 12, color: "var(--muted)" }}>
                  The tenant password policy isn&apos;t readable from here — the server still enforces it on submit.
                </div>
              )}
            </div>
          </>
        )}
        <div>
          <label className="field-label" htmlFor={orgFieldId}>
            Organization
          </label>
          {orgs.length ? (
            <SelectInput id={orgFieldId} value={org?.name ?? ""} options={orgs.map((o) => o.name)} onChange={setOrgNameSel} />
          ) : (
            <div style={{ fontSize: 13, color: "var(--muted)" }}>No organization you can add users to.</div>
          )}
        </div>
      </SectionCard>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" disabled={!valid} pending={busy} onClick={create}>
          {isHuman ? "Create & invite" : "Create service account"}
        </Btn>
      </div>
    </FullPage>
  );
}

/** The state values the Users filter offers, mapped to the enum the API takes.
 * "Deleted" is offered explicitly because an absent `state` now EXCLUDES
 * soft-deleted rows server-side — the console used to hide them client-side
 * while `total` still counted them. */
const USER_STATES: { label: string; value?: number }[] = [
  { label: "All states" },
  { label: "Active", value: 1 },
  { label: "Inactive", value: 2 },
  { label: "Deleted", value: 3 },
  { label: "Locked", value: 4 },
  { label: "Initial", value: 5 },
];

const USER_TYPES: { label: string; value?: number }[] = [
  { label: "All", value: undefined },
  { label: "Human", value: 1 },
  { label: "Machine", value: 2 },
];

export function UsersView() {
  const { me, accessibleOrgs } = useConsole();
  const router = useRouter();
  const canCreate = canWriteAnyOrg(me, USER_WRITE_ROLES);

  // urlSync: this table's narrowing IS the URL, so a filtered view pastes into
  // a ticket and reopens as itself.
  const list = usePagedList(pages.users, "users", { urlSync: true });
  const stateLabel = USER_STATES.find((s) => s.value === list.query.state)?.label ?? "All states";
  const typeLabel = USER_TYPES.find((t) => t.value === list.query.type)?.label ?? "All";

  const columns: Column<User>[] = [
    {
      key: "user",
      header: "User",
      sort: "username",
      fixed: true,
      text: (u) => `${userDisplay(u)} (${u.username})`,
      cell: (u) => (
        <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {u.userType === 2 ? (
            <span style={{ width: 28, height: 28, borderRadius: 8, background: "var(--field)", border: "1px solid var(--border)", display: "grid", placeItems: "center", color: "var(--muted)", flexShrink: 0 }}>
              <Icon name="terminal" size={15} />
            </span>
          ) : (
            <Avatar name={userDisplay(u)} size={28} />
          )}
          <span style={{ minWidth: 0 }}>
            <span style={{ display: "block", fontWeight: 600 }}>{userDisplay(u)}</span>
            <span style={{ display: "block", fontSize: 12, color: "var(--muted)", fontFamily: "var(--font-mono)" }}>{u.username}</span>
          </span>
        </span>
      ),
    },
    {
      key: "org",
      header: "Organization",
      text: (u) => orgName(accessibleOrgs, u.orgId),
      cell: (u) => orgName(accessibleOrgs, u.orgId),
    },
    {
      key: "type",
      header: "Type",
      text: (u) => (u.userType === 2 ? "Machine" : "Human"),
      cell: (u) =>
        u.userType === 2 ? (
          <span className="badge gray">
            <Icon name="terminal" size={11} sw={2.2} />
            Machine
          </span>
        ) : (
          <span className="badge accent">Human</span>
        ),
    },
    {
      key: "email",
      header: "Email",
      className: "hide-md",
      text: (u) => u.human?.email ?? "",
      cell: (u) =>
        u.human?.email ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
            <span className="mono">{u.human.email}</span>
            {u.human.emailVerified ? (
              <Icon name="check" size={13} sw={2.6} style={{ color: "var(--success)" }} />
            ) : (
              <Icon name="alert" size={13} sw={2} style={{ color: "var(--warn)" }} />
            )}
          </span>
        ) : (
          <span className="mono">—</span>
        ),
    },
    {
      key: "state",
      header: "State",
      sort: "state",
      text: (u) => LABELS.userState[u.state] ?? String(u.state),
      cell: (u) => <UserStateBadge state={u.state} />,
    },
    {
      key: "lastAuth",
      header: "Last auth",
      className: "hide-md mono",
      // Empty means the user has never authenticated — a distinct fact from an
      // unknown one, and the column is blank for every pre-existing user until
      // their next login (last_auth_at was not backfilled).
      text: (u) => orNever(u.lastAuth),
      cell: (u) => <Ts value={u.lastAuth} empty="Never" />,
    },
    {
      key: "created",
      header: "Created",
      className: "hide-md mono",
      sort: "created",
      defaultDir: "desc",
      text: (u) => u.created,
      cell: (u) => <Ts value={u.created} />,
    },
  ];

  const bulk: BulkAction<User>[] = canCreate
    ? [
        {
          label: "Deactivate",
          icon: "ban",
          destructive: true,
          applies: (u) => u.state === 1,
          describe: userDisplay,
          run: (u) => usersApi.deactivate(u.id),
          confirm: (n) => ({
            title: `Deactivate ${n} ${n === 1 ? "user" : "users"}?`,
            body: "Each account can no longer sign in. Existing sessions are not terminated by this action — sign them out separately. Reactivating restores access.",
            confirmLabel: "Deactivate",
            destructive: true,
          }),
        },
        {
          label: "Sign out everywhere",
          icon: "logout",
          destructive: true,
          // A tenant manager only, the same gate the endpoint carries.
          applies: () => canManageTenant(me),
          describe: userDisplay,
          run: (u) => sessionsApi.revokeForUser(u.id),
          confirm: (n) => ({
            title: `Sign ${n} ${n === 1 ? "user" : "users"} out everywhere?`,
            body: "Every login session ends and every token grant is revoked, refresh tokens included, so they must sign in again on every device. Access tokens already issued stay valid at the relying party until they expire.",
            confirmLabel: "Sign out everywhere",
            destructive: true,
          }),
        },
      ]
    : [];

  return (
    <div className="fade-in">
      <PageHead
        page="users"
        sub="Human and machine identities. Each user belongs to one organization; usernames are unique per tenant."
        actions={
          canCreate && (
            <>
              <Link className="btn primary" href="/users/new">
                <Icon name="plus" size={15} sw={2.2} />
                New user
              </Link>
            </>
          )
        }
      />

      <DataTable
        id="users"
        list={list}
        columns={columns}
        rowKey={(u) => u.id}
        onRowClick={(u) => router.push(`/users/${u.id}`)}
        noun="user"
        empty="No users match this filter."
        exportName="users"
        bulk={bulk.length ? bulk : undefined}
        search={{ fields: "the username", placeholder: "Search username…" }}
        filters={
          <>
            <Seg
              options={USER_TYPES.map((t) => t.label)}
              value={typeLabel}
              onChange={(l) => list.setQuery({ type: USER_TYPES.find((t) => t.label === l)?.value })}
            />
            <SelectInput
              width={150}
              value={stateLabel}
              options={USER_STATES.map((s) => s.label)}
              onChange={(l) => list.setQuery({ state: USER_STATES.find((s) => s.label === l)?.value })}
            />
          </>
        }
      />
    </div>
  );
}
