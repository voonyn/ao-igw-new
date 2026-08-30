"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Icon } from "@/components/console/icons";
import { EntityHeader, FullPage, SectionCard } from "@/components/console/overlays";
import { Btn, confirmAction, Field, ViewNotice } from "@/components/console/primitives";
import { useConsole, usePending } from "@/components/console/store";
import { PageHead } from "@/components/console/page-head";
import { rowActivation } from "@/components/console/data-table";
import {
  canManageTenant,
  canWriteOrg,
  describeStatus,
  mutationMessage,
  notificationsApi,
  type NotificationSettings,
  type NotificationSettingsBody,
  type NotificationTemplate,
  type NotificationTemplateInfo,
  type OrgRef,
  type Outcome,
  type RenderedTemplate,
} from "@/lib/console-api";

/** The noun `describeStatus` builds every notifications sentence from. */
const NOTIFICATIONS_RESOURCE = "notification settings";

const TRANSPORTS = [
  { v: "log", label: "Log (no send — dev/testing)" },
  { v: "smtp", label: "SMTP" },
];
const TLS_MODES = [
  { v: "starttls", label: "STARTTLS (587)" },
  { v: "tls", label: "Implicit TLS (465)" },
  { v: "none", label: "None (dev only)" },
];

/** The tenant-scope reads, taken on the server during the render. The route
 * passes them; picking an organization reads that scope from the browser. */
export interface NotificationsSeed {
  settings?: Outcome<NotificationSettings>;
  templates?: NotificationTemplateInfo[];
}

export function NotificationsView({ initial }: { initial?: NotificationsSeed } = {}) {
  const { A, me } = useConsole();
  const tenantManager = canManageTenant(me);
  // Orgs whose templates the caller may manage: every org for a tenant
  // manager, else the orgs where the caller is an ORG_OWNER.
  const manageableOrgs = useMemo(
    () => me.accessibleOrgs.filter((o) => canWriteOrg(me, o.id, ["ORG_OWNER"])),
    [me],
  );

  if (!tenantManager && manageableOrgs.length === 0) {
    // Pre-emptive refusal, same sentence a 403 would produce: the console
    // decides it here only because it can, not because it means something else.
    const gate = describeStatus({ state: "forbidden" }, NOTIFICATIONS_RESOURCE, "IAM_OWNER or IAM_ADMIN", "ORG_OWNER")!;
    return (
      <div className="fade-in">
        <PageHead
          page="notifications"
          sub="Delivery settings and message templates for this tenant."
        />
        <ViewNotice title={gate.title} body={gate.body} icon="lock" />
      </div>
    );
  }

  return <NotificationsManager tenantManager={tenantManager} manageableOrgs={manageableOrgs} toast={A.toast} initial={initial} />;
}

function NotificationsManager({
  tenantManager,
  manageableOrgs,
  toast,
  initial,
}: {
  tenantManager: boolean;
  manageableOrgs: OrgRef[];
  toast: (msg: string, icon?: string, severity?: "success" | "error" | "info") => void;
  /** The tenant-scope reads, taken on the server during the render. They seed
   * the first paint. Picking an organization reads that scope from the browser,
   * and so does every write. */
  initial?: NotificationsSeed;
}) {
  // The seed is the tenant read, so it counts only when the tenant scope is the
  // one on screen. An org manager opens on its own scope and reads it here.
  const seed = tenantManager ? initial : undefined;
  const [settings, setSettings] = useState<NotificationSettings | null>(seed?.settings?.ok ? seed.settings.data : null);
  const [templates, setTemplates] = useState<NotificationTemplateInfo[] | null>(seed?.templates ?? null);
  const [openKey, setOpenKey] = useState<string | null>(null);
  // Templates scope: "" = tenant default (tenant managers only); else an org id.
  const [scope, setScope] = useState<string>(tenantManager ? "" : manageableOrgs[0]?.id ?? "");

  // EH-4, same shape as audit.tsx: `loaded` flips in `finally`, so a failed read
  // renders an error instead of a card that stays blank forever.
  const [settingsLoaded, setSettingsLoaded] = useState(Boolean(seed?.settings));
  // Title AND body come from `describeStatus`, so a refusal reads as one
  // sentence rather than a view-specific headline over a shared body.
  const [settingsError, setSettingsError] = useState<{ title: string; body: string } | null>(
    seed?.settings && !seed.settings.ok
      ? describeStatus({ state: seed.settings.reason }, NOTIFICATIONS_RESOURCE, "IAM_OWNER or IAM_ADMIN", "ORG_OWNER")
      : null
  );

  // The server already answered both tenant reads. The two mount effects below
  // would repeat them, so each is skipped once.
  const seededSettings = useRef(Boolean(seed?.settings));
  const seededTemplates = useRef(Boolean(seed?.templates));

  const loadSettings = useCallback(() => {
    return notificationsApi
      .getSettings()
      .then((out) => {
        if (out.ok) {
          setSettingsError(null);
          setSettings(out.data);
          return;
        }
        // A refused read gets the shared sentence, not "Something went wrong."
        setSettingsError(describeStatus({ state: out.reason }, NOTIFICATIONS_RESOURCE, "IAM_OWNER or IAM_ADMIN", "ORG_OWNER"));
      })
      .catch((e: unknown) =>
        setSettingsError({ title: "Couldn’t load delivery settings", body: mutationMessage(e) }),
      )
      .finally(() => setSettingsLoaded(true));
  }, []);

  const loadTemplates = useCallback(() => {
    notificationsApi
      .templates(scope || undefined)
      .then(setTemplates)
      .catch((e) => toast(mutationMessage(e), "alert", "error"));
  }, [toast, scope]);

  useEffect(() => {
    if (seededSettings.current) {
      seededSettings.current = false;
      return;
    }
    if (tenantManager) void loadSettings();
  }, [tenantManager, loadSettings]);

  useEffect(() => {
    if (seededTemplates.current) {
      seededTemplates.current = false;
      return;
    }
    loadTemplates();
  }, [loadTemplates]);

  if (openKey)
    return (
      <TemplateEditorPage
        templateKey={openKey}
        scope={scope}
        onClose={() => setOpenKey(null)}
        onChanged={loadTemplates}
        toast={toast}
      />
    );

  return (
    <div className="fade-in">
      <PageHead
        page="notifications"
        sub={
          <>
            How this tenant sends mail (password resets, verifications, invitations) and the templates it uses. Falls
            back to the tenant default when unset.
          </>
        }
      />

      {tenantManager && settingsError && (
        <ViewNotice
          title={settingsError.title}
          body={settingsError.body}
          onRetry={() => void loadSettings()}
          pending={!settingsLoaded}
        />
      )}
      {tenantManager && settings && !settingsError && (
        <SettingsForm settings={settings} onSaved={loadSettings} />
      )}
      {tenantManager && <TestSend />}
      <TemplatesCard
        templates={templates}
        scope={scope}
        onScope={setScope}
        tenantManager={tenantManager}
        orgs={manageableOrgs}
        onOpen={setOpenKey}
      />
    </div>
  );
}

function SettingsForm({ settings, onSaved }: { settings: NotificationSettings; onSaved: () => void }) {
  const passwordId = useId();
  const [transport, setTransport] = useState(settings.transport || "log");
  const [smtpHost, setHost] = useState(settings.smtpHost);
  // Held as the raw input text, not a number: `Number("")` is 0, so clearing
  // the box would submit port 0 / a zero-second timeout rather than nothing.
  const [smtpPort, setPort] = useState(String(settings.smtpPort || 587));
  const [smtpUsername, setUsername] = useState(settings.smtpUsername);
  const [password, setPassword] = useState(""); // write-only; empty = keep stored
  const [changePassword, setChangePassword] = useState(false);
  const [fromAddress, setFrom] = useState(settings.fromAddress);
  const [fromName, setFromName] = useState(settings.fromName);
  const [tlsMode, setTlsMode] = useState(settings.tlsMode || "starttls");
  const [timeout, setTimeout] = useState(String(settings.sendTimeoutSeconds || 10));
  const [saving, run] = usePending();

  const isSmtp = transport === "smtp";
  const portNum = Number(smtpPort);
  const timeoutNum = Number(timeout);
  const portBad = isSmtp && (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535);
  const timeoutBad = !Number.isInteger(timeoutNum) || timeoutNum < 1 || timeoutNum > 300;

  async function save() {
    const body: NotificationSettingsBody = {
      transport,
      smtpHost: smtpHost.trim(),
      smtpPort: portNum,
      smtpUsername: smtpUsername.trim(),
      fromAddress: fromAddress.trim(),
      fromName: fromName.trim(),
      tlsMode,
      sendTimeoutSeconds: timeoutNum,
    };
    // Only send the password when the operator chose to change it (write-only).
    if (changePassword) body.smtpPassword = password;
    const done = await run(() => notificationsApi.updateSettings(body), { ok: "Settings saved", after: onSaved });
    if (done) {
      setChangePassword(false);
      setPassword("");
    }
  }

  return (
    <div className="card" style={{ padding: 20, marginBottom: 18 }}>
      {/* `configured` is the API's own answer to "can this transport send as it
          stands": the log transport always can, and SMTP needs a host and a from
          address. Reading it here is what stops the screen looking configured
          while every message goes nowhere. */}
      <div className="sect-title" style={{ marginBottom: 14, display: "flex", alignItems: "center", gap: 10 }}>
        Delivery settings
        {settings.configured ? (
          <span className="badge green">
            <span className="bdot" />
            ready to send
          </span>
        ) : (
          <span className="badge amber">incomplete — nothing sends</span>
        )}
      </div>
      {!settings.configured && (
        <div style={{ fontSize: 12.5, color: "var(--muted)", marginBottom: 12 }}>
          The SMTP transport needs a host and a from address before the gateway can deliver a message.
        </div>
      )}

      <Field label="Transport">
        <select className="text-input" value={transport} onChange={(e) => setTransport(e.target.value)}>
          {TRANSPORTS.map((t) => (
            <option key={t.v} value={t.v}>
              {t.label}
            </option>
          ))}
        </select>
      </Field>

      {isSmtp && (
        <>
          <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
            <div style={{ flex: 2 }}>
              <Field label="SMTP host">
                <input className="text-input" value={smtpHost} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" />
              </Field>
            </div>
            <div style={{ flex: 1 }}>
              <Field label="Port">
                <input
                  className="text-input"
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={65535}
                  step={1}
                  value={smtpPort}
                  aria-invalid={portBad}
                  onChange={(e) => setPort(e.target.value)}
                />
              </Field>
            </div>
          </div>

          <Field label="Username" style={{ marginTop: 12 }}>
            <input className="text-input" value={smtpUsername} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
          </Field>

          <label className="field-label" style={{ marginTop: 12 }} htmlFor={passwordId}>
            Password
          </label>
          {settings.passwordSet && !changePassword ? (
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
                placeholder={settings.passwordSet ? "Enter a new password" : "SMTP password"}
                autoComplete="new-password"
              />
              {settings.passwordSet && (
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

          <Field label="TLS mode" style={{ marginTop: 12 }}>
            <select className="text-input" value={tlsMode} onChange={(e) => setTlsMode(e.target.value)}>
              {TLS_MODES.map((m) => (
                <option key={m.v} value={m.v}>
                  {m.label}
                </option>
              ))}
            </select>
          </Field>
        </>
      )}

      <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
        <div style={{ flex: 2 }}>
          <Field label="From address">
            <input className="text-input" value={fromAddress} onChange={(e) => setFrom(e.target.value)} placeholder="noreply@example.com" />
          </Field>
        </div>
        <div style={{ flex: 2 }}>
          <Field label="From name">
            <input className="text-input" value={fromName} onChange={(e) => setFromName(e.target.value)} placeholder="Example" />
          </Field>
        </div>
        <div style={{ flex: 1 }}>
          <Field label="Timeout (s)">
            <input
            className="text-input"
            type="number"
            inputMode="numeric"
            min={1}
            max={300}
            step={1}
            value={timeout}
            aria-invalid={timeoutBad}
            onChange={(e) => setTimeout(e.target.value)}
          />
          </Field>
        </div>
      </div>

      <div style={{ display: "flex", marginTop: 16 }}>
        <Btn className="btn primary" style={{ marginLeft: "auto" }} disabled={portBad || timeoutBad} pending={saving} onClick={save}>
          Save settings
        </Btn>
      </div>
    </div>
  );
}

function TestSend() {
  const [to, setTo] = useState("");
  const [template, setTemplate] = useState("password_reset");
  const [sending, run] = usePending();

  async function send() {
    if (!to.trim()) return;
    // A test send changes nothing in the console, so skip the full refetch.
    await run(() => notificationsApi.sendTest(to.trim(), template), { ok: "Test message sent", after: () => {} });
  }

  return (
    <div className="card" style={{ padding: 20, marginBottom: 18 }}>
      <div className="sect-title" style={{ marginBottom: 6 }}>
        Send a test
      </div>
      <div style={{ fontSize: 12.5, color: "var(--muted)", marginBottom: 12 }}>
        Delivers a diagnostic message using this tenant&apos;s current settings, so you can verify configuration.
      </div>
      <div style={{ display: "flex", gap: 12, alignItems: "flex-end" }}>
        <div style={{ flex: 2 }}>
          <Field label="Recipient">
            <input className="text-input" value={to} onChange={(e) => setTo(e.target.value)} placeholder="you@example.com" />
          </Field>
        </div>
        <div style={{ flex: 1 }}>
          <Field label="Template">
            <select className="text-input" value={template} onChange={(e) => setTemplate(e.target.value)}>
              <option value="password_reset">password_reset</option>
              <option value="email_verification">email_verification</option>
              <option value="member_invitation">member_invitation</option>
              <option value="passkey_registered">passkey_registered</option>
            </select>
          </Field>
        </div>
        <Btn className="btn" disabled={!to.trim()} pending={sending} onClick={send}>
          <Icon name="send" size={14} /> Send test
        </Btn>
      </div>
    </div>
  );
}

// sourceBadge renders a template's effective origin for the current scope.
function sourceBadge(source: string, scope: string) {
  if (source === "org") return <span className="badge accent">org override</span>;
  if (source === "tenant") {
    // At the tenant scope this row IS the override; at an org scope it is inherited.
    return <span className="badge accent">{scope ? "inherited (tenant)" : "override"}</span>;
  }
  return <span className="badge">default</span>;
}

function TemplatesCard({
  templates,
  scope,
  onScope,
  tenantManager,
  orgs,
  onOpen,
}: {
  templates: NotificationTemplateInfo[] | null;
  scope: string;
  onScope: (scope: string) => void;
  tenantManager: boolean;
  orgs: OrgRef[];
  onOpen: (key: string) => void;
}) {
  const scopeId = useId();
  return (
    <div className="card" style={{ overflow: "auto hidden" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "14px 16px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div className="sect-title" style={{ margin: 0 }}>
          Message templates
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
          <label className="field-label" style={{ margin: 0 }} htmlFor={scopeId}>
            Scope
          </label>
          <select
            id={scopeId}
            className="text-input"
            style={{ width: "auto", minWidth: 180 }}
            value={scope}
            onChange={(e) => onScope(e.target.value)}
          >
            {tenantManager && <option value="">Tenant default</option>}
            {orgs.map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </select>
        </div>
      </div>
      <table className="tbl" aria-label="Message templates">
        <thead>
          <tr>
            <th scope="col">Template</th>
            <th scope="col">Source</th>
          </tr>
        </thead>
        <tbody>
          {(templates ?? []).map((t) => (
            <tr key={t.key} {...rowActivation(() => onOpen(t.key))}>
              <td className="mono" style={{ fontWeight: 600 }}>
                {t.key}
              </td>
              <td>{sourceBadge(t.source, scope)}</td>
            </tr>
          ))}
          {templates && templates.length === 0 && (
            <tr>
              <td colSpan={2} style={{ color: "var(--muted)", textAlign: "center", padding: 24 }}>
                No templates.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function TemplateEditorPage({
  templateKey,
  scope,
  onClose,
  onChanged,
  toast,
}: {
  templateKey: string;
  scope: string;
  onClose: () => void;
  onChanged: () => void;
  toast: (msg: string, icon?: string, severity?: "success" | "error" | "info") => void;
}) {
  const [tmpl, setTmpl] = useState<NotificationTemplate | null>(null);
  const [subject, setSubject] = useState("");
  const [bodyText, setBodyText] = useState("");
  const [bodyHtml, setBodyHtml] = useState("");
  const [preview, setPreview] = useState<RenderedTemplate | null>(null);
  const [saving, run] = usePending();
  const orgId = scope || undefined;
  const scopeLabel = scope ? "organization" : "tenant";

  useEffect(() => {
    notificationsApi
      .template(templateKey, orgId)
      .then((t) => {
        setTmpl(t);
        setSubject(t.subject);
        setBodyText(t.bodyText);
        setBodyHtml(t.bodyHtml);
      })
      .catch((e) => toast(mutationMessage(e), "alert", "error"));
  }, [templateKey, orgId, toast]);

  async function doPreview() {
    try {
      setPreview(await notificationsApi.preview(templateKey, orgId));
    } catch (e) {
      toast(mutationMessage(e), "alert", "error");
    }
  }

  async function save() {
    const done = await run(() => notificationsApi.upsertTemplate(templateKey, { subject, bodyText, bodyHtml }, orgId), {
      ok: "Template saved",
      after: onChanged,
    });
    if (done) onClose();
  }

  async function revert() {
    const fallback = scope ? "tenant default" : "built-in default";
    const ok = await confirmAction({
      title: `Revert “${templateKey}” to the ${fallback}?`,
      body: `This ${scopeLabel} override is deleted, not disabled — the wording, subject, and branding it carries are gone and every message of this type is sent using the ${fallback} from the next send onwards.`,
      confirmLabel: "Revert to default",
      destructive: true,
    });
    if (!ok) return;
    if (await run(() => notificationsApi.deleteTemplate(templateKey, orgId), { ok: "Override removed", after: onChanged })) onClose();
  }

  const canSave = subject.trim() !== "" && bodyText.trim() !== "" && bodyHtml.trim() !== "";

  return (
    <FullPage backLabel="Notifications" crumb={templateKey} onBack={onClose}>
      <EntityHeader
        tile={
          <span className="entity-tile">
            <Icon name="mail" size={26} />
          </span>
        }
        title={<span style={{ fontFamily: "var(--font-mono)" }}>{templateKey}</span>}
        meta={
          <>
            <span className="badge">{scope ? "Organization scope" : "Tenant scope"}</span>
            {tmpl?.isOverride ? (
              <span className="badge accent">{scope ? "org override" : "tenant override"}</span>
            ) : (
              <span className="badge">default (inherited)</span>
            )}
          </>
        }
      />

      <SectionCard title="Variables" desc="Go template syntax available in the subject and both bodies.">
        <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
          e.g. <span className="mono">{"{{.DisplayName}}"}</span>, <span className="mono">{"{{.Link}}"}</span>,{" "}
          <span className="mono">{"{{.Code}}"}</span>.
        </div>
      </SectionCard>

      <SectionCard
        title="Content"
        desc={`Subject and message bodies. Editing creates ${scope ? "an organization" : "a tenant"} override.`}
      >
        <div>
          <Field label="Subject">
            <input className="text-input" value={subject} onChange={(e) => setSubject(e.target.value)} />
          </Field>
        </div>
        <div>
          <Field label="Text body">
            <textarea
              className="text-input"
              style={{ minHeight: 120, fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              value={bodyText}
              onChange={(e) => setBodyText(e.target.value)}
            />
          </Field>
        </div>
        <div>
          <Field label="HTML body">
            <textarea
              className="text-input"
              style={{ minHeight: 140, fontFamily: "var(--font-mono)", fontSize: 12.5 }}
              value={bodyHtml}
              onChange={(e) => setBodyHtml(e.target.value)}
            />
          </Field>
        </div>
      </SectionCard>

      <SectionCard
        title="Preview"
        desc="Render this template with sample data to verify the output before saving."
      >
        <div>
          <button type="button" className="btn sm ghost" onClick={doPreview}>
            <Icon name="eye" size={13} /> Render with sample data
          </button>
        </div>
        {preview && (
          <div>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>Subject</div>
            <div style={{ fontWeight: 600, marginBottom: 8 }}>{preview.subject}</div>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>Text</div>
            <pre style={{ whiteSpace: "pre-wrap", fontSize: 12.5, marginBottom: 8 }}>{preview.text}</pre>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>HTML</div>
            <iframe title="html preview" srcDoc={preview.html} style={{ width: "100%", height: 200, border: "1px solid var(--border)", borderRadius: 6, background: "#fff" }} />
          </div>
        )}
      </SectionCard>

      {tmpl?.isOverride && (
        <SectionCard
          danger
          title="Danger zone"
          desc={`Remove this ${scopeLabel} override and revert "${templateKey}" to the ${scope ? "tenant default" : "built-in default"}.`}
        >
          <div>
            <Btn className="btn danger-ghost" pending={saving} onClick={revert}>
              <Icon name="ban" size={15} /> Revert to default
            </Btn>
          </div>
        </SectionCard>
      )}

      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onClose}>
          Cancel
        </button>
        <Btn className="btn primary" disabled={!canSave} pending={saving} onClick={save}>
          Save override
        </Btn>
      </div>
    </FullPage>
  );
}
