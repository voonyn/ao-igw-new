"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Icon } from "@/components/console/icons";
import { Btn, confirmAction, ViewNotice } from "@/components/console/primitives";
import { useConsole, usePending } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import {
  authPolicyApi,
  canManageTenant,
  canWriteOrg,
  describeStatus,
  type AuthPolicy,
  type AuthPolicyBody,
  type OrgRef,
  type Outcome,
} from "@/lib/console-api";

/** The noun `describeStatus` builds every auth-policy sentence from. */
const POLICIES_RESOURCE = "auth policy";

// A month, in seconds — the ceiling for the duration knobs. Long enough for any
// real policy, short enough that a fat-fingered extra digit is caught here.
const MONTH = 2592000;

// Numeric knobs, in display order. Durations are seconds (what the API takes).
// BL-7: every field declares min/max so the browser rejects an out-of-range
// value, and a cleared field is refused rather than silently submitted as 0 —
// which on `lockoutThreshold` means "lockout disabled".
const NUM_FIELDS: { key: keyof AuthPolicyBody; label: string; hint: string; min: number; max: number }[] = [
  { key: "lockoutThreshold", label: "Lockout threshold", hint: "Failed attempts before the account locks. 0 disables lockout.", min: 0, max: 1000 },
  { key: "lockoutWindowSeconds", label: "Lockout window (seconds)", hint: "Attempts older than this start a fresh count.", min: 0, max: MONTH },
  { key: "lockoutCooldownSeconds", label: "Lockout cooldown (seconds)", hint: "How long a lock lasts before it auto-expires.", min: 0, max: MONTH },
  { key: "pwMinLength", label: "Password min length", hint: "Minimum characters (0–72).", min: 0, max: 72 },
  { key: "pwMinClasses", label: "Password min character classes", hint: "Distinct lower/upper/digit/symbol (0–4).", min: 0, max: 4 },
  { key: "recoveryResetTtlSeconds", label: "Password-reset token TTL (seconds)", hint: "Lifetime of a reset link.", min: 60, max: MONTH },
  { key: "recoveryVerifyTtlSeconds", label: "Email-verify token TTL (seconds)", hint: "Lifetime of a verification link.", min: 60, max: MONTH },
];

const BOUNDS = new Map(NUM_FIELDS.map((f) => [f.key as string, f]));

/** Why `raw` is not an acceptable value for `key`, or null when it is. */
function numProblem(key: string, raw: string): string | null {
  const f = BOUNDS.get(key);
  if (!f) return null;
  if (raw.trim() === "") return `${f.label} is empty — enter a number (a blank field is not 0).`;
  const n = Number(raw);
  if (!Number.isInteger(n)) return `${f.label} must be a whole number.`;
  if (n < f.min || n > f.max) return `${f.label} must be between ${f.min} and ${f.max}.`;
  return null;
}

export function PoliciesView({ initial }: { initial?: Outcome<AuthPolicy> } = {}) {
  const { me } = useConsole();
  const tenantManager = canManageTenant(me);
  // Orgs whose override the caller may manage: every org for an tenant manager,
  // else the orgs where the caller is an ORG_OWNER.
  const manageableOrgs = useMemo(
    () => me.accessibleOrgs.filter((o) => canWriteOrg(me, o.id, ["ORG_OWNER"])),
    [me],
  );

  if (!tenantManager && manageableOrgs.length === 0) {
    // Pre-emptive refusal, same sentence a 403 would produce: the console
    // decides it here only because it can, not because it means something else.
    const gate = describeStatus({ state: "forbidden" }, POLICIES_RESOURCE, "IAM_OWNER or IAM_ADMIN", "ORG_OWNER")!;
    return (
      <div className="fade-in">
        <PageHead
          page="policies"
          sub="Lockout, password, and recovery-token rules for this tenant."
        />
        <ViewNotice title={gate.title} body={gate.body} icon="lock" />
      </div>
    );
  }

  return <AuthPolicyManager tenantManager={tenantManager} manageableOrgs={manageableOrgs} initial={initial} />;
}

function AuthPolicyManager({
  tenantManager,
  manageableOrgs,
  initial,
}: {
  tenantManager: boolean;
  manageableOrgs: OrgRef[];
  /** The tenant-default policy, read on the server during the render. It seeds
   * the first paint, and it applies only while the scope is still the tenant —
   * picking an organization reads that override from the browser. */
  initial?: Outcome<AuthPolicy>;
}) {
  const scopeId = useId();
  // Scope: "" = tenant default (tenant managers only); else an org id override.
  const [scope, setScope] = useState<string>(tenantManager ? "" : manageableOrgs[0]?.id ?? "");
  // The seed is the tenant read, so it counts only when the tenant scope is the
  // one on screen. An org manager opens on its own override and reads it here.
  const seed = tenantManager ? initial : undefined;
  const [pol, setPol] = useState<AuthPolicy | null>(seed?.ok ? seed.data : null);

  // Same shape as audit.tsx: a refused read resolves to the shared sentence, and
  // `loaded` flips either way so a 403 can never leave the card on "Loading…".
  const [error, setError] = useState<{ title: string; body: string } | null>(
    seed && !seed.ok ? describeStatus({ state: seed.reason }, POLICIES_RESOURCE, "IAM_OWNER or IAM_ADMIN", "ORG_OWNER") : null
  );
  const [loaded, setLoaded] = useState(Boolean(seed));

  // The server already answered the tenant scope. The mount effect below would
  // repeat that request, so it is skipped once.
  const seeded = useRef(Boolean(seed));

  const load = useCallback(() => {
    return authPolicyApi
      .get(scope || undefined)
      .then((out) => {
        if (out.ok) {
          setError(null);
          setPol(out.data);
        } else {
          setError(describeStatus({ state: out.reason }, POLICIES_RESOURCE, "IAM_OWNER or IAM_ADMIN", "ORG_OWNER"));
        }
      })
      .catch((e: unknown) =>
        setError(describeStatus({ state: "error", message: e instanceof Error ? e.message : "" }, POLICIES_RESOURCE)),
      )
      .finally(() => setLoaded(true));
  }, [scope]);

  useEffect(() => {
    if (seeded.current) {
      seeded.current = false;
      return;
    }
    load();
  }, [load]);

  // pol may still hold the previous scope's response until the new fetch resolves;
  // the API echoes orgId, so only render the form once it matches the current scope.
  const ready = pol && pol.orgId === scope;

  return (
    <div className="fade-in">
      <PageHead
        page="policies"
        sub={
          <>
            Lockout, password strength, and recovery-token lifetimes. The tenant default governs every
            organization; an organization override changes only the fields it sets and inherits the rest.
            A field the tenant does not set keeps the gateway default.
          </>
        }
      />

      <div className="card" style={{ padding: 16, marginBottom: 18, display: "flex", alignItems: "center", gap: 12 }}>
        <label className="field-label" style={{ margin: 0 }} htmlFor={scopeId}>
          Scope
        </label>
        <select
          id={scopeId}
          className="text-input"
          style={{ width: "auto", minWidth: 220 }}
          value={scope}
          onChange={(e) => setScope(e.target.value)}
        >
          {tenantManager && <option value="">Tenant default</option>}
          {manageableOrgs.map((o) => (
            <option key={o.id} value={o.id}>
              {o.name} (override)
            </option>
          ))}
        </select>
      </div>

      {error ? (
        <ViewNotice title={error.title} body={error.body} onRetry={() => void load()} pending={!loaded} />
      ) : ready ? (
        <PolicyForm key={scope} pol={pol} scope={scope} onReload={load} />
      ) : (
        <div className="card" style={{ padding: 24, color: "var(--muted)" }}>Loading…</div>
      )}
    </div>
  );
}

function PolicyForm({ pol, scope, onReload }: { pol: AuthPolicy; scope: string; onReload: () => void }) {
  // One prefix per form instance; each field appends its own key.
  const fieldId = useId();
  const isOrg = scope !== "";
  // Held as the raw input text, not a number: `Number("")` is 0, and submitting
  // that on `lockoutThreshold` silently turns lockout off (BL-7).
  const [num, setNum] = useState<Record<string, string>>(() => ({
    lockoutThreshold: String(pol.lockoutThreshold),
    lockoutWindowSeconds: String(pol.lockoutWindowSeconds),
    lockoutCooldownSeconds: String(pol.lockoutCooldownSeconds),
    pwMinLength: String(pol.pwMinLength),
    pwMinClasses: String(pol.pwMinClasses),
    recoveryResetTtlSeconds: String(pol.recoveryResetTtlSeconds),
    recoveryVerifyTtlSeconds: String(pol.recoveryVerifyTtlSeconds),
  }));
  const [breach, setBreach] = useState(pol.pwCheckBreach);
  const [mfaRequired, setMfaRequired] = useState(pol.mfaRequired);
  const [deny, setDeny] = useState(pol.pwDenyList.join("\n"));
  // Which fields are set at THIS scope, as the API reports them. It answers
  // `overridden` truthfully at the tenant scope too: a tenant that never stored a
  // field reads the gateway default, and the console used to render that as the
  // tenant's own setting.
  const [over, setOver] = useState<Set<string>>(
    () => new Set(Object.entries(pol.overridden).filter(([, v]) => v).map(([k]) => k)),
  );
  const [saving, run] = usePending();

  // A field is editable when it is set at this scope. There is a level below
  // either scope: the tenant default under an organization, and the gateway
  // default under the tenant.
  const active = (key: string) => over.has(key);
  // What an unset field falls back to at this scope.
  const inheritedFrom = isOrg ? "Inherited from the tenant default." : "Not set — the gateway default applies.";

  // Only fields actually being written are validated — an inherited field is
  // sent as null and its input is disabled.
  const problems = NUM_FIELDS.filter((f) => active(f.key as string))
    .map((f) => numProblem(f.key as string, num[f.key as string]))
    .filter((p): p is string => p !== null);
  const toggleOver = (key: string, on: boolean) =>
    setOver((s) => {
      const next = new Set(s);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });

  async function save() {
    if (problems.length > 0) return;
    // A field that is not set here is sent as null, so it keeps inheriting the
    // level below: the tenant default at an org scope, and the gateway default at
    // the tenant scope. Sending the resolved value instead would freeze today's
    // gateway default into the row.
    const val = <T,>(key: string, v: T): T | null => (active(key) ? v : null);
    const n = (key: string) => val(key, Number(num[key]));
    const body: AuthPolicyBody = {
      lockoutThreshold: n("lockoutThreshold"),
      lockoutWindowSeconds: n("lockoutWindowSeconds"),
      lockoutCooldownSeconds: n("lockoutCooldownSeconds"),
      pwMinLength: n("pwMinLength"),
      pwMinClasses: n("pwMinClasses"),
      pwCheckBreach: val("pwCheckBreach", breach),
      pwDenyList: val(
        "pwDenyList",
        deny.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
      ),
      recoveryResetTtlSeconds: n("recoveryResetTtlSeconds"),
      recoveryVerifyTtlSeconds: n("recoveryVerifyTtlSeconds"),
      mfaRequired: val("mfaRequired", mfaRequired),
    };
    await run(() => authPolicyApi.update(body, scope || undefined), { ok: "Auth policy saved", after: onReload });
  }

  async function reset() {
    const ok = await confirmAction({
      title: "Remove this organization's override?",
      body: "Every field this organization overrides reverts to the tenant default immediately — including any stricter lockout or password rule set here. The override is deleted, not disabled.",
      confirmLabel: "Remove override",
      destructive: true,
    });
    if (!ok) return;
    await run(() => authPolicyApi.reset(scope), { ok: "Override removed", after: onReload });
  }

  function numField(key: string, label: string, hint: string) {
    const on = active(key);
    const f = BOUNDS.get(key);
    const problem = on ? numProblem(key, num[key]) : null;
    return (
      <div style={{ marginBottom: 14 }} key={key}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <label className="field-label" style={{ margin: 0 }} htmlFor={fieldId + key}>
            {label}
          </label>
          <OverrideToggle isOrg={isOrg} on={over.has(key)} onChange={(v) => toggleOver(key, v)} />
        </div>
        <input
          id={fieldId + key}
          className="text-input"
          type="number"
          inputMode="numeric"
          min={f?.min}
          max={f?.max}
          step={1}
          value={num[key]}
          disabled={!on}
          aria-invalid={!!problem}
          onChange={(e) => setNum((s) => ({ ...s, [key]: e.target.value }))}
        />
        <div style={{ fontSize: 11.5, color: problem ? "var(--error)" : "var(--muted-2)", marginTop: 4 }}>
          {problem ?? (on ? hint : inheritedFrom)}
        </div>
      </div>
    );
  }

  const lockoutFields = NUM_FIELDS.slice(0, 3);
  const pwNumFields = NUM_FIELDS.slice(3, 5);
  const recoveryFields = NUM_FIELDS.slice(5);

  return (
    <>
      <div className="card" style={{ padding: 20, marginBottom: 18 }}>
        <div className="sect-title" style={{ marginBottom: 14 }}>
          Lockout
        </div>
        {lockoutFields.map((f) => numField(f.key, f.label, f.hint))}
      </div>

      <div className="card" style={{ padding: 20, marginBottom: 18 }}>
        <div className="sect-title" style={{ marginBottom: 14 }}>
          Password
        </div>
        {/* These rules reach a local password only. A person an identity provider
            owns holds no local password, so the directory owns the rules and the
            change. Saying so here stops an administrator from tightening a screen
            that governs nobody they had in mind. */}
        <div style={{ fontSize: 12.5, color: "var(--muted)", marginBottom: 14 }}>
          These rules govern local passwords only. They do not apply to a person an identity
          provider owns: that person signs in against the directory, holds no password here,
          and changes it in the directory. The directory owns those rules.
        </div>
        {pwNumFields.map((f) => numField(f.key, f.label, f.hint))}

        <div style={{ marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="field-label" style={{ margin: 0 }}>Check breached passwords (Have I Been Pwned)</span>
            <OverrideToggle isOrg={isOrg} on={over.has("pwCheckBreach")} onChange={(v) => toggleOver("pwCheckBreach", v)} />
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={breach}
              disabled={!active("pwCheckBreach")}
              onChange={(e) => setBreach(e.target.checked)}
            />
            {active("pwCheckBreach") ? "Reject known-breached passwords" : inheritedFrom}
          </label>
        </div>

        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <label className="field-label" style={{ margin: 0 }} htmlFor={fieldId + "pwDenyList"}>
              Deny-list (one per line; a list set here replaces the one below)
            </label>
            <OverrideToggle isOrg={isOrg} on={over.has("pwDenyList")} onChange={(v) => toggleOver("pwDenyList", v)} />
          </div>
          <textarea
            id={fieldId + "pwDenyList"}
            className="text-input"
            style={{ minHeight: 90, fontFamily: "var(--font-mono)", fontSize: 12.5 }}
            value={deny}
            disabled={!active("pwDenyList")}
            placeholder="password&#10;companyname&#10;letmein"
            onChange={(e) => setDeny(e.target.value)}
          />
        </div>
      </div>

      <div className="card" style={{ padding: 20, marginBottom: 18 }}>
        <div className="sect-title" style={{ marginBottom: 14 }}>
          Account recovery
        </div>
        {recoveryFields.map((f) => numField(f.key, f.label, f.hint))}
      </div>

      <div className="card" style={{ padding: 20, marginBottom: 18 }}>
        <div className="sect-title" style={{ marginBottom: 14 }}>
          Multi-factor authentication
        </div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="field-label" style={{ margin: 0 }}>Require two-factor authentication (TOTP)</span>
            <OverrideToggle isOrg={isOrg} on={over.has("mfaRequired")} onChange={(v) => toggleOver("mfaRequired", v)} />
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={mfaRequired}
              disabled={!active("mfaRequired")}
              onChange={(e) => setMfaRequired(e.target.checked)}
            />
            {active("mfaRequired")
              ? "Force users to set up an authenticator app on next sign-in"
              : inheritedFrom}
          </label>
        </div>
      </div>

      {isOrg && (
        <div className="card danger" style={{ padding: 20, marginBottom: 18 }}>
          <div className="sect-title" style={{ marginBottom: 6 }}>
            Danger zone
          </div>
          <div style={{ fontSize: 12.5, color: "var(--muted)", marginBottom: 12 }}>
            Remove this organization&apos;s override so it fully inherits the tenant default.
          </div>
          <Btn className="btn danger-ghost" pending={saving} onClick={reset}>
            <Icon name="ban" size={15} /> Reset to tenant default
          </Btn>
        </div>
      )}

      <div className="form-actions" style={{ flexDirection: "column", alignItems: "flex-end", gap: 8 }}>
        {problems.length > 0 && (
          <div style={{ fontSize: 12.5, color: "var(--error)", textAlign: "right" }}>{problems[0]}</div>
        )}
        <Btn className="btn primary" pending={saving} disabled={problems.length > 0} onClick={save}>
          Save policy
        </Btn>
      </div>
    </>
  );
}

/** Whether one field is set at the scope on screen. An organization overrides the
 * tenant default; the tenant overrides the gateway default. Both levels have
 * something below them, so both scopes carry the toggle. */
function OverrideToggle({ isOrg, on, onChange }: { isOrg: boolean; on: boolean; onChange: (v: boolean) => void }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--muted)", marginLeft: "auto" }}>
      <input type="checkbox" checked={on} onChange={(e) => onChange(e.target.checked)} /> {isOrg ? "Override" : "Set here"}
    </label>
  );
}
