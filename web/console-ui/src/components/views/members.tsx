"use client";

import { useEffect, useState } from "react";
import { Icon } from "@/components/console/icons";
import { Avatar, Btn, confirmAction, Field, OptChip, PickerTruncated, Seg, SelectInput, Ts } from "@/components/console/primitives";
import { DataTable, type BulkAction, type Column } from "@/components/console/data-table";
import { FullPage, Menu, SectionCard } from "@/components/console/overlays";
import { useConsole, usePagedList, usePending, type PagedList } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { canWriteOrg, grantableOrgRoles, isIAMOwner, membersApi, notificationsApi, pages, readPicker } from "@/lib/console-api";
import { IAM_ROLES, ORG_ROLES } from "@/lib/data";
import { nameOr, orgName, userDisplay } from "@/lib/helpers";
import type { OrgMember, Page, TenantMember } from "@/lib/types";

// Org roles that may manage org memberships (mirrors the gateway gate).
const MEMBER_WRITE_ROLES = ["ORG_OWNER", "ORG_USER_MANAGER"];

// The two halves of an org membership grant: the picker reaches only accounts
// that already exist (`state === 1`), so an uninvited person is structurally
// unreachable from it — that complement is what the invite mode covers.
const GRANT_MODE = "Existing user";
const INVITE_MODE = "Invite by email";

function RoleEditor({
  roles,
  allRoles,
  readOnly,
  onChange,
}: {
  roles: string[];
  allRoles: string[];
  readOnly: boolean;
  onChange: (roles: string[]) => void;
}) {
  const [adding, setAdding] = useState(false);
  const available = allRoles.filter((r) => !roles.includes(r));
  return (
    <span style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", position: "relative" }}>
      {roles.map((r) => (
        <span key={r} className="chip" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
          {r}
          {!readOnly && roles.length > 1 && (
            <button
              type="button"
              style={{ width: 16, height: 16, border: "none", background: "transparent", color: "var(--muted-2)", cursor: "pointer", display: "grid", placeItems: "center", padding: 0 }}
              aria-label={"Remove " + r}
              onClick={(e) => {
                e.stopPropagation();
                onChange(roles.filter((x) => x !== r));
              }}
            >
              <Icon name="x" size={11} sw={2.4} />
            </button>
          )}
        </span>
      ))}
      {!readOnly && available.length > 0 && (
        <span style={{ position: "relative" }}>
          <button
            type="button"
            className="mono-chip"
            onClick={(e) => {
              e.stopPropagation();
              setAdding((v) => !v);
            }}
          >
            <Icon name="plus" size={11} sw={2.4} />
            role
          </button>
          {adding && (
            <Menu onClose={() => setAdding(false)} align="right">
              {available.map((r) => (
                <button
                  key={r}
                  onClick={() => {
                    onChange(roles.concat([r]));
                    setAdding(false);
                  }}
                >
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{r}</span>
                </button>
              ))}
            </Menu>
          )}
        </span>
      )}
    </span>
  );
}

/** The user ids already holding a membership at this scope, so the picker cannot
 * offer a duplicate. Follows the cursor on the same bound as the picker itself:
 * an exclusion set that stops early would offer a duplicate the write then
 * refuses. */
function useExistingMembers(scope: "tenant" | "org", orgId: string | null): Set<string> {
  const { dataVersion } = useConsole();
  const [ids, setIds] = useState<Set<string>>(new Set());
  useEffect(() => {
    let cancelled = false;
    const read = scope === "tenant" ? pages.tenantMembers : pages.orgMembers;
    readPicker(read, { orgId: scope === "tenant" ? null : orgId })
      .then((out) => {
        if (cancelled || !out.ok) return;
        setIds(new Set((out.data.items ?? []).map((m) => m.userId)));
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [scope, orgId, dataVersion]);
  return ids;
}

function AddMemberPage({
  scope,
  orgId,
  onClose,
}: {
  scope: "tenant" | "org";
  orgId: string | null;
  onClose: () => void;
}) {
  const { accessibleOrgs, me } = useConsole();
  // ponytail: the candidate picker walks the users and the memberships it must
  // exclude to a bounded page count, rather than offering a *Load more* nobody
  // can reach inside a <select>. Swap in a typeahead over a server-side user
  // search if a tenant ever outgrows the bound.
  const userPage = usePagedList(pages.users, "users", {
    picker: true,
    orgId: scope === "tenant" ? null : orgId,
  });
  const existing = useExistingMembers(scope, orgId);
  const candidates = userPage.items.filter((u) => u.state === 1 && !existing.has(u.id));

  // AZ-2: an org-scoped grant must name its organization. There is no fallback
  // to "the first one" — a membership written against the wrong org is a silent
  // privilege grant, so the control stays disabled until one is chosen.
  const targetOrg = scope === "tenant" ? "" : orgId;
  const missingOrg = scope === "org" && !targetOrg;

  // The gateway gates *what* may be granted on top of *whether* — an invitation
  // carries roles, so an unfiltered picker lets an ORG_USER_MANAGER build a
  // request that only ever answers 403 (AuthorizeOrgRoleGrant).
  const allRoles = scope === "tenant" ? IAM_ROLES : grantableOrgRoles(me, targetOrg ?? "", ORG_ROLES);
  const [userName, setUserName] = useState("");
  const [email, setEmail] = useState("");
  const [inviting, setInviting] = useState(false);
  const [roles, setRoles] = useState<string[]>([allRoles[allRoles.length - 1]]);
  const [busy, run] = usePending();

  // Pre-emptive SMTP gate: with no notifier the gateway answers an invitation
  // with 422 "invalid input", blaming a perfectly good email for unwired SMTP.
  // `null` is *unknown* and never disables — the read is instance-manager-only,
  // and a stored settings row still can't prove the notifier built at startup.
  const [smtpConfigured, setSmtpConfigured] = useState<boolean | null>(null);
  useEffect(() => {
    if (scope !== "org") return;
    notificationsApi
      .getSettings()
      .then((out) => setSmtpConfigured(out.ok ? out.data.configured : null))
      .catch(() => setSmtpConfigured(null));
  }, [scope]);
  const smtpOff = smtpConfigured === false;
  const emailValid = /.+@.+\..+/.test(email);

  async function invite() {
    if (!emailValid || roles.length === 0 || missingOrg || smtpOff) return;
    const done = await run(() => membersApi.invite({ email, orgId: targetOrg as string, roles }), {
      ok: "Invitation sent to " + email,
      icon: "mail",
    });
    if (done) onClose();
  }

  async function grant() {
    // Resolve against the loaded page rather than seeding state from it: the
    // candidates arrive after first render, so a seeded default is always empty.
    const u = candidates.find((c) => userDisplay(c) === userName) ?? candidates[0];
    if (!u || roles.length === 0 || missingOrg) return;
    const done = await run(() => membersApi.add({ userId: u.id, orgId: targetOrg as string, roles }), {
      ok: "Granted " + roles.join(", ") + " to " + userName,
      icon: "key",
    });
    if (done) onClose();
  }

  return (
    <FullPage
      backLabel="Members & Roles"
      crumb={scope === "tenant" ? "Add tenant member" : "Add organization member"}
      onBack={onClose}
    >
      <h1 className="entity-title" style={{ margin: "8px 0 4px" }}>
        {scope === "tenant" ? "Add tenant member" : inviting ? "Invite organization member" : "Add organization member"}
      </h1>
      <div className="entity-meta" style={{ marginBottom: 22 }}>
        {scope === "tenant"
          ? "Grants IAM roles at the tenant level."
          : "Grants org roles scoped to one organization."}
      </div>
      <SectionCard
        title="Membership"
        desc={
          inviting
            ? "Email someone who has no account yet. They set their own password from the link, which activates the account with these roles."
            : "Pick an eligible user and the roles to grant. Roles can be edited later from the table."
        }
      >
        {scope === "org" && (
          <Seg
            label="Who is being added"
            options={[GRANT_MODE, INVITE_MODE]}
            value={inviting ? INVITE_MODE : GRANT_MODE}
            onChange={(v) => setInviting(v === INVITE_MODE)}
          />
        )}
        {scope === "org" && (
          <div>
            <span className="field-label">Organization</span>
            <div style={{ fontSize: 13.5, fontWeight: 600 }}>{orgId ? orgName(accessibleOrgs, orgId) : "—"}</div>
            {missingOrg && (
              <div style={{ marginTop: 6, fontSize: 12.5, color: "var(--error)", display: "flex", alignItems: "center", gap: 6 }}>
                <Icon name="alert" size={13} sw={2.2} />
                Choose an organization in the filter first — a membership is never written to a guessed organization.
              </div>
            )}
          </div>
        )}
        {inviting ? (
          <div>
            <Field label="Email">
              <input
                className="text-input"
                type="email"
                placeholder="jane.doe@acme.com"
                value={email}
                disabled={smtpOff}
                onChange={(e) => setEmail(e.target.value)}
              />
            </Field>
            {smtpOff && (
              <div style={{ marginTop: 6, fontSize: 12.5, color: "var(--error)", display: "flex", alignItems: "center", gap: 6 }}>
                <Icon name="alert" size={13} sw={2.2} />
                Email delivery isn&apos;t configured — set up SMTP under Notifications before inviting anyone.
              </div>
            )}
          </div>
        ) : candidates.length === 0 ? (
          <div style={{ fontSize: 13.5, color: "var(--muted)" }}>All eligible users already hold a membership here.</div>
        ) : (
          <div>
            <Field label="User">
              <SelectInput value={userName} options={candidates.map((c) => userDisplay(c))} onChange={setUserName} />
            </Field>
            {userPage.truncated && <PickerTruncated what="users" />}
          </div>
        )}
        <div>
          <span className="field-label" id="member-roles-label">Roles</span>
          <div className="chip-row" role="group" aria-labelledby="member-roles-label">
            {allRoles.map((r) => {
              const on = roles.includes(r);
              return <OptChip key={r} label={r} on={on} onChange={() => setRoles(on ? roles.filter((x) => x !== r) : roles.concat([r]))} />;
            })}
          </div>
        </div>
      </SectionCard>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        {inviting ? (
          <Btn className="btn primary" disabled={!emailValid || roles.length === 0 || missingOrg || smtpOff} pending={busy} onClick={invite}>
            Send invitation
          </Btn>
        ) : (
          <Btn className="btn primary" disabled={candidates.length === 0 || roles.length === 0 || missingOrg} pending={busy} onClick={grant}>
            Grant membership
          </Btn>
        )}
      </div>
    </FullPage>
  );
}

/** The one membership shape both tabs share. `orgId` is absent on the tenant
 * roster, which is exactly what distinguishes a tenant grant from an org one —
 * so an empty one is what `membersApi` reads as "at tenant level". */
type Member = TenantMember | OrgMember;

const rowOrgOf = (m: Member) => (m as { orgId?: string }).orgId ?? "";
const memberKey = (m: Member) => m.userId + rowOrgOf(m);

/** The consequence, worded once. Both the single-row control and the bulk action
 * describe the same write, so they must not describe it differently. */
const REVOKE_BODY =
  "loses every role held there, and with them all access those roles granted — immediately, on existing sessions as well as new ones. The account itself is not deleted; re-adding the membership restores access.";

export function MembersView() {
  const { me, accessibleOrgs } = useConsole();
  const [tab, setTab] = useState("Tenant (IAM)");
  const orgs = accessibleOrgs;
  const [orgNameSel, setOrgNameSel] = useState("All organizations");
  const [adding, setAdding] = useState(false);
  const [busy, run] = usePending();
  const selOrg = orgs.find((o) => o.name === orgNameSel);

  // Two collections, two reads, two cursors. They used to arrive in one envelope
  // whose cursor and total described the org half alone while the tenant roster
  // rode along unpaged — so the roster could carry no count of its own and no
  // way to advance. Each tab now owns a page under the same contract.
  //
  // Only the tenant half claims the URL: both lists stay mounted, and two of them
  // writing the same `sort` would each read the other's.
  const tenantList = usePagedList(pages.tenantMembers, "memberships", { orgId: null, urlSync: true });
  const orgList = usePagedList(pages.orgMembers, "memberships", { orgId: selOrg ? selOrg.id : null });

  const isTenantTab = tab === "Tenant (IAM)";
  const list: PagedList<Page<Member>> = isTenantTab ? tenantList : orgList;
  // AZ-2: no `|| orgs[0]`. With "All organizations" selected there is no target,
  // and Add member stays unavailable rather than picking one for the operator.
  const canManageTenant = isIAMOwner(me);
  const canWriteRow = (m: Member) => (isTenantTab ? canManageTenant : canWriteOrg(me, rowOrgOf(m), MEMBER_WRITE_ROLES));
  const canAdd = isTenantTab ? canManageTenant : !!selOrg && canWriteOrg(me, selOrg.id, MEMBER_WRITE_ROLES);

  async function revoke(m: Member) {
    const rowOrgId = rowOrgOf(m);
    const who = nameOr(m.userName, m.userId);
    const scopeText = rowOrgId ? `the organization “${orgName(accessibleOrgs, rowOrgId)}”` : "this tenant";
    const ok = await confirmAction({
      title: `Revoke ${who}'s membership?`,
      body: `${who} ${REVOKE_BODY.replace("there", `in ${scopeText}`)}`,
      confirmLabel: "Revoke membership",
      destructive: true,
    });
    if (!ok) return;
    await run(() => membersApi.remove(m.userId, rowOrgId), { ok: "Revoked membership for " + who, icon: "ban" });
  }

  // The same `DELETE /members/:userId` the row control issues, once per selected
  // row. A membership the caller cannot write is skipped rather than attempted,
  // so the confirmation counts only what will actually be revoked.
  const revokeBulk: BulkAction<Member> = {
    label: "Revoke",
    icon: "ban",
    destructive: true,
    applies: canWriteRow,
    describe: (m) => nameOr(m.userName, m.userId),
    run: (m) => membersApi.remove(m.userId, rowOrgOf(m)),
    confirm: (n) => ({
      title: `Revoke ${n} ${n === 1 ? "membership" : "memberships"}?`,
      body: `Each member ${REVOKE_BODY}`,
      confirmLabel: "Revoke",
      destructive: true,
    }),
  };

  const columns: Column<Member>[] = [
    {
      key: "user",
      header: "User",
      fixed: true,
      text: (m) => nameOr(m.userName, m.userId),
      cell: (m) => {
        const who = nameOr(m.userName, m.userId);
        return (
          <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Avatar name={who} size={28} />
            <span style={{ minWidth: 0 }}>
              <span style={{ display: "block", fontWeight: 600 }}>{who}</span>
              <span style={{ display: "block", fontSize: 12, color: "var(--muted)", fontFamily: "var(--font-mono)" }}>{m.userId}</span>
            </span>
          </span>
        );
      },
    },
    ...(isTenantTab
      ? []
      : [
          {
            key: "org",
            header: "Organization",
            text: (m: Member) => orgName(accessibleOrgs, rowOrgOf(m) || null),
            cell: (m: Member) => orgName(accessibleOrgs, rowOrgOf(m) || null),
          },
        ]),
    {
      key: "roles",
      header: isTenantTab ? "IAM roles" : "Org roles",
      text: (m) => m.roles.join(" "),
      cell: (m) => (
        <RoleEditor
          roles={m.roles}
          // Locked while any membership write is in flight — a role chip is a
          // mutation, so it must not be re-activatable.
          readOnly={!canWriteRow(m) || busy}
          // Same escalation gate the add/invite picker mirrors: a role the
          // caller may not confer is not offered here either.
          allRoles={isTenantTab ? IAM_ROLES : grantableOrgRoles(me, rowOrgOf(m), ORG_ROLES)}
          onChange={(roles) =>
            void run(() => membersApi.updateRoles(m.userId, { orgId: rowOrgOf(m), roles }), {
              ok: "Updated roles for " + nameOr(m.userName, m.userId),
              icon: "key",
            })
          }
        />
      ),
    },
    {
      key: "created",
      header: "Member since",
      className: "hide-md mono",
      sort: "created",
      defaultDir: "desc",
      text: (m) => m.created,
      cell: (m) => <Ts value={m.created} />,
    },
    {
      key: "actions",
      header: "",
      fixed: true,
      cell: (m) =>
        canWriteRow(m) ? (
          <span style={{ display: "block", textAlign: "right" }}>
            <button
              type="button"
              style={{ width: 28, height: 28, border: "none", background: "transparent", color: "var(--muted-2)", cursor: "pointer", borderRadius: 7 }}
              aria-label={"Revoke " + nameOr(m.userName, m.userId) + "'s membership"}
              disabled={busy}
              onClick={() => void revoke(m)}
            >
              <Icon name="x" size={15} />
            </button>
          </span>
        ) : null,
    },
  ];

  if (adding)
    return (
      <AddMemberPage scope={isTenantTab ? "tenant" : "org"} orgId={selOrg ? selOrg.id : null} onClose={() => setAdding(false)} />
    );

  return (
    <div className="fade-in">
      <PageHead
        page="members"
        sub="Role grants from the schema’s membership tables — IAM roles at tenant level, org roles per organization."
        actions={
          (canAdd || (!isTenantTab && !selOrg)) && (
            <>
              <span title={canAdd ? undefined : "Choose a single organization first — a membership is never written to a guessed organization."}>
                <button type="button" className="btn primary" disabled={!canAdd} onClick={() => setAdding(true)}>
                  <Icon name="plus" size={15} sw={2.2} />
                  Add member
                </button>
              </span>
            </>
          )
        }
      />

      <DataTable
        // Distinct ids: the two tabs are different tables with different columns,
        // so they must not share a hidden-column preference or a selection.
        id={isTenantTab ? "tenant-members" : "org-members"}
        list={list}
        columns={columns}
        rowKey={memberKey}
        noun="membership"
        empty={isTenantTab ? "No tenant administrators yet." : "No organization memberships in this scope."}
        exportName={isTenantTab ? "tenant-members" : "org-members"}
        bulk={[revokeBulk]}
        // The role editor opens a menu from inside a cell; a clipping card would
        // cut it off at the table edge.
        overflowVisible
        filters={
          <>
            <Seg options={["Tenant (IAM)", "Organization"]} value={tab} onChange={setTab} />
            {!isTenantTab && (
              <SelectInput width={200} value={orgNameSel} options={["All organizations"].concat(orgs.map((o) => o.name))} onChange={setOrgNameSel} />
            )}
          </>
        }
      />
    </div>
  );
}
