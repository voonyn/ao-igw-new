"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Icon } from "@/components/console/icons";
import { EntityHeader, FullPage, SectionCard } from "@/components/console/overlays";
import { Btn, Cbx, confirmAction, EntityStateBadge, Field, ViewNotice } from "@/components/console/primitives";
import { PageHead } from "@/components/console/page-head";
import { rowActivation } from "@/components/console/data-table";
import { useConsole, usePending } from "@/components/console/store";
import { LABELS } from "@/lib/data";
import { lines, orgName, PAGE_TITLES } from "@/lib/helpers";
import {
  canManageTenant,
  describeStatus,
  identityProvidersApi,
  IDP_MODE_LDAPS,
  IDP_MODE_PLAIN,
  IDP_MODE_SCHEMES,
  IDP_MODE_STARTTLS,
  MutationError,
  mutationMessage,
  UnauthorizedError,
  type ConnectionTestResult,
  type IdentityProvider,
  type IdentityProviderBody,
  type OrgRef,
  type Outcome,
} from "@/lib/console-api";

/** The noun `describeStatus` builds every identity-provider sentence from. */
const IDP_RESOURCE = "identity providers";

/** The role a tenant-wide directory registration needs. */
const IDP_ROLE = "IAM_OWNER or IAM_ADMIN";

const MODES = [
  { v: IDP_MODE_LDAPS, label: "LDAPS — ldaps://, TLS from the first byte" },
  { v: IDP_MODE_STARTTLS, label: "StartTLS — ldap://, upgraded in place" },
  { v: IDP_MODE_PLAIN, label: "Plain — ldap://, no encryption" },
];

/** The two states a directory is written in. `oneof=1 2` on the gateway body:
 * "Removed" is what a soft delete writes, and no form offers it. The words come
 * from `LABELS.entityState`, so the select and the badge cannot drift apart. */
const STATES = [1, 2];

/** The six attributes read from one directory entry.
 *
 * The three required ones are what a person is created from: the stable id, the
 * username, and the email. The other three are names, and a directory that
 * carries none of them still signs somebody in. */
type AttrKey = "attrId" | "attrUsername" | "attrEmail" | "attrFirstName" | "attrLastName" | "attrDisplayName";

const ATTRS: { key: AttrKey; label: string; placeholder: string; required?: boolean; note?: string }[] = [
  {
    key: "attrId",
    label: "Stable id",
    placeholder: "objectGUID",
    required: true,
    note: "The identity link stores this value, so a username changed in the directory never orphans the person.",
  },
  { key: "attrUsername", label: "Username", placeholder: "sAMAccountName", required: true },
  { key: "attrEmail", label: "Email", placeholder: "mail", required: true },
  { key: "attrFirstName", label: "First name (optional)", placeholder: "givenName" },
  { key: "attrLastName", label: "Last name (optional)", placeholder: "sn" },
  { key: "attrDisplayName", label: "Display name (optional)", placeholder: "displayName" },
];

/** What each stage of the connection test tried to do. The test answers a stage
 * name, so the console says which value of the form to look at. */
const STAGE_LABELS: Record<string, string> = {
  dial: "Opening the socket to the server failed.",
  tls: "The TLS handshake failed. Check the transport and the root CA.",
  bind: "The bind with the service credential failed. Check the bind DN and its password.",
  search: "The search failed. Check the base DN, the user base, and the object classes.",
};

/** The slug of a refused save, and the field its sentence sits beside.
 *
 * The console branches on the slug and never on the message text, so a reworded
 * message never moves a sentence. A slug that is not in here reads as a toast,
 * which is what every other console write does. */
const SAVE_ERROR_FIELD: Record<string, "name" | "domains"> = {
  name_conflict: "name",
  domain_already_claimed: "domains",
  last_local_owner: "domains",
};

/** Stated on the list and on the form. The form replaces the list, so an
 * operator who opens it never reads what the list said. */
const POLICY_NOTE =
  "The password policy of this tenant governs nothing for a person a directory owns. The directory owns those rules — length, character classes, deny-list, breach check — and this gateway holds no password for such a person.";

/** The explicit confirmation a plain bind needs. The gateway refuses mode 1
 * without it, and the console must not offer the choice with a softer sentence
 * than the risk it carries. */
const PLAINTEXT_CONFIRM =
  "I understand that passwords travel in clear, and I choose the plain transport.";

/** The domains of this form that another provider of the tenant already holds.
 *
 * The gateway answers `domain_already_claimed` with one sentence and no domain,
 * because the mapped message is fixed. The console holds every other provider of
 * the tenant, so it names the domain itself. */
function claimedBy(mine: string[], others: IdentityProvider[]): string[] {
  const taken = new Set(others.flatMap((p) => p.domains));
  return mine.filter((d) => taken.has(d));
}

export function IdentityProvidersView({ initial }: { initial?: Outcome<IdentityProvider[]> } = {}) {
  const { me } = useConsole();

  // Registering a directory is tenant-wide authority: a claimed domain routes
  // every person of the tenant whose email carries it. The nav hides this item
  // from everybody else, and a typed URL reads the same sentence a 403 gives.
  if (!canManageTenant(me)) {
    const gate = describeStatus({ state: "forbidden" }, IDP_RESOURCE, IDP_ROLE)!;
    return (
      <div className="fade-in">
        <PageHead page="idps" sub="Directories this tenant signs people in against." />
        <ViewNotice title={gate.title} body={gate.body} icon="lock" />
      </div>
    );
  }

  return <IdentityProvidersManager orgs={me.accessibleOrgs} initial={initial} />;
}

function IdentityProvidersManager({ orgs, initial }: { orgs: OrgRef[]; initial?: Outcome<IdentityProvider[]> }) {
  const [rows, setRows] = useState<IdentityProvider[] | null>(initial?.ok ? initial.data : null);
  const [error, setError] = useState<{ title: string; body: string } | null>(
    initial && !initial.ok ? describeStatus({ state: initial.reason }, IDP_RESOURCE, IDP_ROLE) : null,
  );
  // `null` is the list, "new" is the create form, and a row is the edit form.
  const [open, setOpen] = useState<IdentityProvider | "new" | null>(null);

  const load = useCallback(() => {
    return identityProvidersApi
      .list()
      .then((out) => {
        if (!out.ok) {
          setRows([]);
          setError(describeStatus({ state: out.reason }, IDP_RESOURCE, IDP_ROLE));
          return;
        }
        setError(null);
        setRows(out.data);
      })
      .catch((e: unknown) => {
        if (e instanceof UnauthorizedError) throw e;
        setRows([]);
        setError(describeStatus({ state: "error", message: mutationMessage(e) }, IDP_RESOURCE));
      });
  }, []);

  // The server already answered this read, so the mount effect is skipped once.
  const seeded = useRef(Boolean(initial));
  useEffect(() => {
    if (seeded.current) {
      seeded.current = false;
      return;
    }
    void load();
  }, [load]);

  if (open) {
    const provider = open === "new" ? null : open;
    return (
      <ProviderForm
        provider={provider}
        others={(rows ?? []).filter((p) => p.id !== provider?.id)}
        orgs={orgs}
        onClose={() => setOpen(null)}
        onChanged={load}
      />
    );
  }

  return (
    <div className="fade-in">
      <PageHead
        page="idps"
        sub={
          <>
            Directories this tenant signs people in against. A person whose email carries a claimed domain proves their
            password with a bind against that directory. {POLICY_NOTE}
          </>
        }
        actions={
          <button type="button" className="btn primary" onClick={() => setOpen("new")}>
            <Icon name="plus" size={15} sw={2.2} />
            Register a directory
          </button>
        }
      />

      {error ? (
        <ViewNotice title={error.title} body={error.body} onRetry={() => void load()} />
      ) : (
        <div className="card" style={{ overflow: "auto hidden" }}>
          <table className="tbl" aria-label="Identity providers">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Level</th>
                <th scope="col">State</th>
                <th scope="col" className="hide-md">
                  Transport
                </th>
                <th scope="col">Domains</th>
              </tr>
            </thead>
            <tbody>
              {(rows ?? []).map((p) => (
                <tr key={p.id} {...rowActivation(() => setOpen(p))} className="clickable">
                  <td style={{ fontWeight: 600 }}>{p.name}</td>
                  <td>{p.orgId ? orgName(orgs, p.orgId) : "Tenant-wide"}</td>
                  <td>
                    <EntityStateBadge state={p.state} />
                  </td>
                  <td className="hide-md mono">{IDP_MODE_SCHEMES[p.mode] ?? p.mode}</td>
                  <td className="mono">{p.domains.length > 0 ? p.domains.join(", ") : "—"}</td>
                </tr>
              ))}
              {rows && rows.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ color: "var(--muted)", textAlign: "center", padding: 24 }}>
                    No directories registered.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ProviderForm({
  provider,
  others,
  orgs,
  onClose,
  onChanged,
}: {
  /** The provider being edited, or null to register a new one. */
  provider: IdentityProvider | null;
  /** Every other provider of the tenant, so a claimed domain can be named. */
  others: IdentityProvider[];
  orgs: OrgRef[];
  onClose: () => void;
  onChanged: () => Promise<void>;
}) {
  const isNew = provider === null;
  const passwordId = useId();

  const [name, setName] = useState(provider?.name ?? "");
  const [state, setState] = useState(provider?.state ?? 1);
  // The level. "" is the tenant-wide provider, and a UUID is that organization's
  // own. A provider stays at the level it was created at, so an edit shows it.
  const [level, setLevel] = useState(provider?.orgId ?? "");
  const [defaultOrgId, setDefaultOrgId] = useState(provider?.defaultOrgId ?? "");

  const [mode, setMode] = useState(provider?.mode ?? IDP_MODE_LDAPS);
  const [plaintextOk, setPlaintextOk] = useState(false);
  const [servers, setServers] = useState((provider?.servers ?? []).join("\n"));
  const [rootCa, setRootCa] = useState(provider?.rootCa ?? "");
  // Held as the raw input text, not a number: `Number("")` is 0, so clearing the
  // box would submit a zero-second deadline rather than nothing.
  const [timeoutText, setTimeoutText] = useState(String(provider?.timeoutSeconds ?? 5));

  const [bindDn, setBindDn] = useState(provider?.bindDn ?? "");
  const [password, setPassword] = useState(""); // write-only; empty = keep stored
  const [changePassword, setChangePassword] = useState(false);
  const [baseDn, setBaseDn] = useState(provider?.baseDn ?? "");
  const [userBase, setUserBase] = useState(provider?.userBase ?? "");
  const [objectClasses, setObjectClasses] = useState((provider?.userObjectClasses ?? []).join("\n"));
  const [filters, setFilters] = useState((provider?.userFilters ?? []).join("\n"));

  const [attrs, setAttrs] = useState<Record<AttrKey, string>>({
    attrId: provider?.attrId ?? "",
    attrUsername: provider?.attrUsername ?? "",
    attrEmail: provider?.attrEmail ?? "",
    attrFirstName: provider?.attrFirstName ?? "",
    attrLastName: provider?.attrLastName ?? "",
    attrDisplayName: provider?.attrDisplayName ?? "",
  });

  const [domains, setDomains] = useState((provider?.domains ?? []).join("\n"));

  const [fieldError, setFieldError] = useState<{ field: "name" | "domains"; text: string } | null>(null);
  const [result, setResult] = useState<ConnectionTestResult | null>(null);
  const [saving, runSave] = usePending();
  const [testing, runTest] = usePending();

  const serverList = useMemo(() => lines(servers), [servers]);
  const domainList = useMemo(() => lines(domains).map((d) => d.toLowerCase()), [domains]);

  const scheme = IDP_MODE_SCHEMES[mode];
  // The gateway refuses a server string that does not match the transport. This
  // marks the box before the save, so the operator never reads a 422 for it.
  const schemeBad = serverList.some((s) => !s.toLowerCase().startsWith(scheme));
  const timeoutNum = Number(timeoutText);
  const timeoutBad = !Number.isInteger(timeoutNum) || timeoutNum < 1 || timeoutNum > 60;
  // A plain bind puts the password of every person on the wire in clear, so the
  // gateway refuses mode 1 without an explicit confirmation.
  const plaintextPending = mode === IDP_MODE_PLAIN && !plaintextOk;
  // `users.org_id` is mandatory, so a tenant-wide provider that names no
  // organization would create nobody.
  const defaultOrgMissing = level === "" && defaultOrgId === "";

  const canSubmit =
    name.trim() !== "" &&
    serverList.length > 0 &&
    !schemeBad &&
    !timeoutBad &&
    !plaintextPending &&
    !defaultOrgMissing &&
    bindDn.trim() !== "" &&
    baseDn.trim() !== "" &&
    lines(objectClasses).length > 0 &&
    lines(filters).length > 0 &&
    ATTRS.every((a) => !a.required || attrs[a.key].trim() !== "");

  function body(): IdentityProviderBody {
    const b: IdentityProviderBody = {
      // The level is sent on an update too: the gateway compares it with the
      // stored one and refuses a body that names another.
      orgId: level,
      name: name.trim(),
      state,
      defaultOrgId,
      mode,
      // The checkbox, not the transport. The gateway refuses mode 1 without
      // this flag, and deriving it from `mode` would send `true` on every plain
      // body and defeat the check the gateway makes.
      confirmPlaintext: plaintextOk,
      servers: serverList,
      rootCa: rootCa.trim(),
      timeoutSeconds: timeoutNum,
      bindDn: bindDn.trim(),
      baseDn: baseDn.trim(),
      userObjectClasses: lines(objectClasses),
      userFilters: lines(filters),
      userBase: userBase.trim(),
      attrId: attrs.attrId.trim(),
      attrUsername: attrs.attrUsername.trim(),
      attrEmail: attrs.attrEmail.trim(),
      attrFirstName: attrs.attrFirstName.trim(),
      attrLastName: attrs.attrLastName.trim(),
      attrDisplayName: attrs.attrDisplayName.trim(),
      domains: domainList,
    };
    // Write-only, and an empty box is never sent. An absent field keeps the
    // stored credential, so leaving the box empty on an edit keeps what is
    // stored — including after the operator opened it and typed nothing.
    //
    // "" would clear the credential, and no screen offers that: a directory
    // with no bind credential answers nothing to a search.
    if (password !== "") b.bindPassword = password;
    return b;
  }

  /** The sentence one refused save reads.
   *
   * The slug decides the sentence and the field, never the message text. A
   * claimed domain is the one case the console can say more about than the
   * gateway: the mapped message names no domain, and the console holds the
   * domains every other provider of this tenant claims. */
  function refusal(e: MutationError): string {
    if (e.code === "domain_already_claimed") {
      const taken = claimedBy(domainList, others);
      if (taken.length > 0) {
        return `${taken.join(", ")} is already claimed by another identity provider of this tenant.`;
      }
    }
    return mutationMessage(e);
  }

  async function save() {
    setFieldError(null);
    const write = () =>
      (isNew ? identityProvidersApi.create(body()) : identityProvidersApi.update(provider.id, body())).catch(
        (e: unknown) => {
          if (e instanceof MutationError && SAVE_ERROR_FIELD[e.code]) {
            setFieldError({ field: SAVE_ERROR_FIELD[e.code], text: refusal(e) });
          }
          throw e;
        },
      );

    // A save closes the form, the way the template editor does. Staying open
    // would hold the row this write replaced, so the stored-credential badge and
    // the domains would report what was on screen before the save.
    if (await runSave(write, { ok: isNew ? "Directory registered" : "Directory saved", after: onChanged })) onClose();
  }

  async function test() {
    // The form on screen is what is tested, so an operator checks values nobody
    // saved yet. A stored provider is named in the path, which is how the test
    // runs without retyping a write-only bind password.
    setResult(null);
    await runTest(() => identityProvidersApi.test(body(), provider?.id).then(setResult), {
      after: async () => {},
    });
  }

  async function del() {
    const ok = await confirmAction({
      title: `Delete the directory “${provider!.name}”?`,
      body: `Every person tied to this directory stops signing in immediately, and the ${provider!.domains.length} domain claim(s) it holds are released. The people it created keep their accounts and hold no password here, so grant them one or register the directory again.`,
      confirmLabel: "Delete directory",
      destructive: true,
    });
    if (!ok) return;
    if (await runSave(() => identityProvidersApi.remove(provider!.id), { ok: "Directory deleted", after: onChanged })) {
      onClose();
    }
  }

  return (
    <FullPage backLabel={PAGE_TITLES.idps} crumb={isNew ? "Register a directory" : provider.name} onBack={onClose}>
      <EntityHeader
        tile={
          <span className="entity-tile">
            <Icon name="link" size={26} />
          </span>
        }
        title={isNew ? "Register a directory" : provider.name}
        meta={
          <>
            <span className="badge">{level ? orgName(orgs, level) : "Tenant-wide"}</span>
            <EntityStateBadge state={state} />
            <span className="badge">LDAP</span>
          </>
        }
      />

      <SectionCard title="Identity" desc={POLICY_NOTE}>
        <div>
          <Field label="Name">
            <input
              className="text-input"
              value={name}
              aria-invalid={fieldError?.field === "name" || undefined}
              onChange={(e) => setName(e.target.value)}
              placeholder="Head office directory"
            />
          </Field>
          {fieldError?.field === "name" && <FieldError text={fieldError.text} />}
        </div>

        <div>
          <Field label="State">
            <select className="text-input" value={state} onChange={(e) => setState(Number(e.target.value))}>
              {STATES.map((s) => (
                <option key={s} value={s}>
                  {LABELS.entityState[s]}
                </option>
              ))}
            </select>
          </Field>
          <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
            An inactive directory refuses every sign-in of the people tied to it, and claims no domain.
          </div>
        </div>

        <div>
          <Field label="Level">
            {isNew ? (
              <select className="text-input" value={level} onChange={(e) => setLevel(e.target.value)}>
                <option value="">Tenant-wide</option>
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </select>
            ) : (
              <input className="text-input" value={level ? orgName(orgs, level) : "Tenant-wide"} readOnly />
            )}
          </Field>
          <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
            A directory stays at the level it was created at. Moving one would relocate every person the next bind
            creates.
          </div>
        </div>

        {level === "" && (
          <div>
            <Field label="Organization for new people">
              <select
                className="text-input"
                value={defaultOrgId}
                aria-invalid={defaultOrgMissing || undefined}
                onChange={(e) => setDefaultOrgId(e.target.value)}
              >
                <option value="">Choose an organization…</option>
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </select>
            </Field>
            <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
              Required at the tenant level. Every person the first bind creates lands in this organization.
            </div>
          </div>
        )}
      </SectionCard>

      <SectionCard title="Transport" desc="How the gateway reaches the directory. Certificate checks are always on.">
        <div>
          <Field label="Transport">
            <select className="text-input" value={mode} onChange={(e) => setMode(Number(e.target.value))}>
              {MODES.map((m) => (
                <option key={m.v} value={m.v}>
                  {m.label}
                </option>
              ))}
            </select>
          </Field>
        </div>

        {mode === IDP_MODE_PLAIN && (
          <div
            style={{
              padding: 14,
              borderRadius: 10,
              background: "var(--warn-soft)",
              border: "1px solid color-mix(in srgb, var(--warn) 40%, transparent)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600, marginBottom: 6, color: "var(--warn)" }}>
              <Icon name="alert" size={16} />
              A plain bind sends the password of every person in clear.
            </div>
            <div style={{ fontSize: 12.5, color: "var(--muted)", marginBottom: 10 }}>
              Every sign-in carries a typed password over this connection, and so does every re-proof in the portal.
              Anybody on the path between this gateway and the directory reads them. Choose StartTLS or LDAPS unless the
              two hosts share a link nobody else reaches.
            </div>
            {/* `Cbx` is a button with role="checkbox", so the sentence rides on
                its `aria-label` rather than on a `<label>` that wraps it. */}
            <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
              <Cbx on={plaintextOk} onChange={setPlaintextOk} label={PLAINTEXT_CONFIRM} />
              <span>{PLAINTEXT_CONFIRM}</span>
            </div>
          </div>
        )}

        <div>
          <Field label={`Servers (one per line; each must start with ${scheme})`}>
            <textarea
              className="text-input"
              style={{ minHeight: 72, fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              value={servers}
              aria-invalid={schemeBad || undefined}
              onChange={(e) => setServers(e.target.value)}
              placeholder={`${scheme}dc1.corp.example:${mode === IDP_MODE_LDAPS ? "636" : "389"}`}
            />
          </Field>
          {schemeBad && <FieldError text={`This transport takes ${scheme}. Fix every server that starts otherwise.`} />}
        </div>

        <div>
          <Field label="Dial and bind timeout (seconds)">
            <input
              className="text-input"
              type="number"
              inputMode="numeric"
              min={1}
              max={60}
              step={1}
              value={timeoutText}
              aria-invalid={timeoutBad || undefined}
              onChange={(e) => setTimeoutText(e.target.value)}
            />
          </Field>
        </div>

        <div>
          <Field label="Root CA (PEM, optional)">
            <textarea
              className="text-input"
              style={{ minHeight: 90, fontFamily: "var(--font-mono)", fontSize: 12 }}
              value={rootCa}
              onChange={(e) => setRootCa(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
            />
          </Field>
          <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
            Only for a private authority. Leave it empty when a public authority signed the certificate.
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="Bind and search"
        desc="The service credential this gateway binds with, and where it looks for a person."
      >
        <div>
          <Field label="Bind DN">
            <input
              className="text-input"
              value={bindDn}
              onChange={(e) => setBindDn(e.target.value)}
              placeholder="cn=gateway,ou=service,dc=corp,dc=example"
              autoComplete="off"
            />
          </Field>
        </div>

        <div>
          <label className="field-label" htmlFor={passwordId}>
            Bind password
          </label>
          {/* Write-only. No read path answers the value in any shape, so the
              view renders the boolean the API sends and nothing else. */}
          {!isNew && provider.bindPasswordSet && !changePassword ? (
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span className="badge accent">configured</span>
              <button type="button" className="btn sm ghost" onClick={() => setChangePassword(true)}>
                Change
              </button>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <input
                id={passwordId}
                className="text-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isNew ? "Bind password" : "Enter a new password"}
                autoComplete="new-password"
              />
              {!isNew && provider.bindPasswordSet && (
                <button
                  type="button"
                  className="btn sm ghost"
                  onClick={() => {
                    setChangePassword(false);
                    setPassword("");
                  }}
                >
                  Cancel
                </button>
              )}
            </div>
          )}
          {!isNew && !provider.bindPasswordSet && (
            <div style={{ fontSize: 12.5, color: "var(--muted)" }}>No bind password is stored for this directory.</div>
          )}
        </div>

        <div>
          <Field label="Base DN">
            <input
              className="text-input"
              value={baseDn}
              onChange={(e) => setBaseDn(e.target.value)}
              placeholder="dc=corp,dc=example"
            />
          </Field>
        </div>

        <div>
          <Field label="User base (optional, relative to the base DN)">
            <input
              className="text-input"
              value={userBase}
              onChange={(e) => setUserBase(e.target.value)}
              placeholder="ou=people"
            />
          </Field>
        </div>

        <div>
          <Field label="User object classes (one per line)">
            <textarea
              className="text-input"
              style={{ minHeight: 64, fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              value={objectClasses}
              onChange={(e) => setObjectClasses(e.target.value)}
              placeholder={"inetOrgPerson\nuser"}
            />
          </Field>
        </div>

        <div>
          <Field label="Identifier attributes (one per line)">
            <textarea
              className="text-input"
              style={{ minHeight: 64, fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              value={filters}
              onChange={(e) => setFilters(e.target.value)}
              placeholder={"uid\nsAMAccountName\nmail"}
            />
          </Field>
          <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
            What a person types at the identifier step is matched against these attributes.
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="Attributes"
        desc="Six attributes are read from the directory entry. A later bind changes none of them: a rename in the directory never arrives here."
      >
        {ATTRS.map((a) => (
          <div key={a.key}>
            <Field label={a.label}>
              <input
                className="text-input"
                value={attrs[a.key]}
                onChange={(e) => setAttrs({ ...attrs, [a.key]: e.target.value })}
                placeholder={a.placeholder}
              />
            </Field>
            {a.note && <div style={{ fontSize: 12.5, color: "var(--muted)" }}>{a.note}</div>}
          </div>
        ))}
      </SectionCard>

      <SectionCard
        title="Domains"
        desc="A person whose email address carries one of these domains signs in against this directory, whether or not this gateway holds a password for them."
      >
        <div>
          <Field label="Claimed domains (one per line)">
            <textarea
              className="text-input"
              style={{ minHeight: 72, fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              value={domains}
              aria-invalid={fieldError?.field === "domains" || undefined}
              onChange={(e) => setDomains(e.target.value)}
              placeholder="corp.example"
            />
          </Field>
          {fieldError?.field === "domains" && <FieldError text={fieldError.text} />}
        </div>
      </SectionCard>

      <SectionCard
        title="Connection test"
        desc="Dials the servers on this form, binds with the credential, and runs one search. It takes nobody's password and it creates nobody."
      >
        <div>
          <Btn className="btn" disabled={!canSubmit} pending={testing} onClick={test}>
            <Icon name="send" size={14} /> Run the test
          </Btn>
          {!isNew && provider.bindPasswordSet && !changePassword && (
            <div style={{ fontSize: 12.5, color: "var(--muted)", marginTop: 8 }}>
              The stored bind password is used. It is never sent back to this screen.
            </div>
          )}
        </div>
        {result && (
          <div className="card" style={{ padding: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span className={"badge" + (result.ok ? " green" : " amber")}>{result.ok ? "passed" : result.stage}</span>
              <span style={{ fontWeight: 600 }}>
                {result.ok
                  ? `Every stage passed. The search matched ${result.matched} entr${result.matched === 1 ? "y" : "ies"}.`
                  : (STAGE_LABELS[result.stage] ?? "The test failed.")}
              </span>
            </div>
            {result.detail && (
              <pre style={{ whiteSpace: "pre-wrap", fontSize: 12.5, margin: 0 }}>{result.detail}</pre>
            )}
          </div>
        )}
      </SectionCard>

      {!isNew && (
        <SectionCard
          danger
          title="Danger zone"
          desc="Delete this directory. Every person tied to it stops signing in, and the domains it claims are released."
        >
          <div>
            <Btn className="btn danger-ghost" pending={saving} onClick={del}>
              <Icon name="ban" size={15} /> Delete directory
            </Btn>
          </div>
        </SectionCard>
      )}

      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" disabled={!canSubmit} pending={saving} onClick={save}>
          {isNew ? "Register directory" : "Save directory"}
        </Btn>
      </div>
    </FullPage>
  );
}

/** One refusal, rendered beside the field it names. */
function FieldError({ text }: { text: string }) {
  return (
    <div role="alert" style={{ fontSize: 12.5, color: "var(--error)", marginTop: 6 }}>
      {text}
    </div>
  );
}
