package http

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/healthcheck"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	apioidc "alphaomega/identitygateway/internal/api/oidc"
	"alphaomega/identitygateway/internal/application"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/authpolicy"
	"alphaomega/identitygateway/internal/di"
	"alphaomega/identitygateway/internal/notification"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/project"
	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/tenant"
	"alphaomega/identitygateway/internal/user"
)

// loginPrefix is where the login UI reaches the login steps.
const loginPrefix = "/api/v1/login"

// adminPrefix is where the console reaches the admin management API.
const adminPrefix = "/api/v1/admin"

// accountPrefix is where the portal reaches the self-service account API.
const accountPrefix = "/api/v1/account"

// capabilitiesPath is where every front end reads what this deployment runs. It
// is open, and it carries no tenant and no person.
const capabilitiesPath = "/api/v1/capabilities"

func Routes(app *fiber.App, cfg *config.Config, bdb *bun.DB, rdb cache.Client, log logger.Logger) error {
	app.Use(requestid.New())
	app.Use(middlewares.RequestLog(log))

	healthCheckHandler(app)

	// Whether this deployment runs a Scan Verifier. Both front ends read the one
	// answer, so there is one switch and not two that drift apart. The value also
	// gates the Digital Identity routes and every outbound call.
	digitalIdentity := digitalIdentityOn(cfg.DI, log)
	mountCapabilities(app, digitalIdentity)

	// The outbound client is built only when the integration is on. A nil client
	// is the switch every caller reads.
	var diClient *di.Client
	if digitalIdentity {
		diClient = di.New(cfg.DI, log)
	}

	// The cipher seals the private signing keys, the protocol state, and the
	// login sessions at rest. A nil cipher stores them as plain JSON, which
	// server startup allows in development only.
	var cipher *crypto.Cipher
	if cfg.Database.EncryptionKey != "" {
		var err error
		if cipher, err = crypto.NewCipher(cfg.Database.EncryptionKey); err != nil {
			return fmt.Errorf("build cipher: %w", err)
		}
	}

	// Every request resolves its tenant from the host, so both stacks share one
	// middleware.
	lookup := middlewares.DBLookup(
		tenant.NewRepository(bdb, log),
		oidc.NewProviderRepository(bdb, log),
	)
	tenantMW := middlewares.Tenant(lookup, cfg.OIDC.TenantHeader, log)

	// The audit trail is written on the caller's transaction, so one recorder
	// serves both stacks.
	recorder := audit.NewRecorder(audit.NewRepository(bdb, log).Insert, log)

	storage := oidc.NewStorageRepository(bdb, cipher, log)

	// The scopes of a tenant reach both stacks: the protocol engine advertises
	// them and releases their claims, and the consent screen renders their
	// words. One repository serves all three reads.
	scopeRepo := oidc.NewScopeRepository(bdb, log)
	scopes := oidc.NewScopeService(oidc.ScopeDeps{List: scopeRepo.List, Log: log})
	claims := oidc.NewClaimsService(oidc.ClaimsDeps{
		Mappers: scopeRepo.Mappers,
		Profile: scopeRepo.Profile,
		Log:     log,
	})

	// One transaction manager serves both stacks. The login steps take it as a
	// service dependency, and the token endpoint takes it as a middleware.
	tx := db.NewTxManager(bdb)

	// The login session service serves both stacks. The login UI drives it, and
	// an RP-initiated logout ends a session through it, so it is built once here
	// and handed to each stack.
	sessions := newSessionService(bdb, rdb, cipher, recorder, tx.RunInTx, log)

	mountOIDCRoutes(app, cfg, bdb, storage, scopes, claims, recorder, cipher, sessions, tenantMW, tx.RunInTx, log)
	mountLogin(app, cfg, bdb, cipher, storage, scopes, recorder, sessions, tenantMW, tx.RunInTx, log)
	mountAdmin(app, bdb, rdb, cipher, storage, recorder, cfg.Notification, diClient, tenantMW, tx.RunInTx, log)
	mountAccount(app, bdb, rdb, cipher, storage, recorder, tenantMW, tx.RunInTx, log)

	return nil
}

// mountOIDCRoutes builds the protocol stack: the domain services each provider
// reads, and the registry that caches one provider per tenant.
func mountOIDCRoutes(
	app *fiber.App, cfg *config.Config, bdb *bun.DB, storage *oidc.StorageRepository,
	scopes *oidc.ScopeService, claims *oidc.ClaimsService,
	recorder *audit.Recorder, cipher *crypto.Cipher, sessions *session.Service,
	tenantMW fiber.Handler, tx db.TxRunner, log logger.Logger,
) {
	build := apioidc.NewBuilder(apioidc.Services{
		PathPrefix: cfg.OIDC.PathPrefix,
		LoginURL:   cfg.App.LoginURL,
		Terminate:  sessions.TerminateByID,
		Keys:       oidc.NewKeyService(oidc.NewKeyRepository(bdb, log), cipher, log),
		Clients:    oidc.NewClientService(oidc.NewClientRepository(bdb, log), log),
		Storage:    storage,
		Scopes:     scopes,
		Claims:     claims,
		Audit:      recorder,
		Log:        log,
	})

	mountOIDC(app, cfg.OIDC.PathPrefix, tenantMW, apioidc.NewRegistry(build, log), tx, log)
}

// mountLogin builds the login stack the login UI drives. Only the login UI
// reaches it, so the group carries the PAT check before the tenant lookup.
func mountLogin(
	app *fiber.App, cfg *config.Config, bdb *bun.DB, cipher *crypto.Cipher,
	storage *oidc.StorageRepository, scopes *oidc.ScopeService, recorder *audit.Recorder,
	svc *session.Service, tenantMW fiber.Handler, tx db.TxRunner, log logger.Logger,
) {
	consents := oidc.NewConsentRepository(bdb, log)
	consent := oidc.NewConsentService(oidc.ConsentDeps{
		Find:  consents.Find,
		Save:  consents.Save,
		InTx:  tx,
		Audit: recorder,
		Log:   log,
	})
	complete := apioidc.NewCompleter(apioidc.CompleterDeps{
		PathPrefix: cfg.OIDC.PathPrefix,
		Find:       storage.FindSession,
		Save:       storage.SaveSession,
		Decide:     consent.Decide,
		Approve:    consent.Approve,
		Deny:       consent.Deny,
		Log:        log,
	})

	group := app.Group(loginPrefix, middlewares.LoginPAT(cfg.Auth.LoginPATs(), log), tenantMW)
	session.Routes(group, session.NewHandler(svc, complete, scopes.Describe, log))
}

// mountAdmin builds the admin management API the console drives.
//
// The group carries the tenant lookup and then the bearer guard, so a handler
// below reads a resolved tenant and a verified subject. The guard admits only a
// token minted for the admin resource identifier, so a token of the account API
// never reaches these routes.
//
// Every admin write runs in one transaction and records one audit event on it,
// so the group takes the same recorder and the same transaction runner the login
// stack takes.
func mountAdmin(
	app *fiber.App, bdb *bun.DB, rdb cache.Client, cipher *crypto.Cipher,
	storage *oidc.StorageRepository, recorder *audit.Recorder,
	notify config.NotificationConfig, diClient *di.Client, tenantMW fiber.Handler,
	tx db.TxRunner, log logger.Logger,
) {
	keyRepo := oidc.NewKeyRepository(bdb, log)
	keys := oidc.NewKeyService(keyRepo, cipher, log)
	bearer := middlewares.Bearer(keys.PublicKeySet, oidc.ResourceAdminAPI, log)

	users := user.NewRepository(bdb, log)
	tenants := tenant.NewRepository(bdb, log)
	orgs := organization.NewRepository(bdb, log)
	providers := oidc.NewProviderRepository(bdb, log)

	// The lockout, password, and recovery rules of the tenant, and the override
	// of each organization. A read resolves the two levels, and a write
	// replaces one of them.
	policies := authpolicy.NewRepository(bdb, log)
	policySvc := authpolicy.NewService(authpolicy.Deps{
		Find:        policies.Find,
		Upsert:      policies.Upsert,
		Remove:      policies.Remove,
		Org:         orgs.FindByID,
		TenantRoles: tenants.MemberRoles,
		Memberships: orgs.ListMemberships,
		InTx:        tx,
		Audit:       recorder,
		Log:         log,
	})

	svc := user.NewService(user.Deps{
		Find:           users.FindByID,
		Tenant:         tenants.FindByID,
		Domains:        tenants.ListDomains,
		TenantRoles:    tenants.MemberRoles,
		Orgs:           orgs.ListByTenant,
		OrgMemberships: orgs.ListMemberships,

		List:         users.List,
		Read:         users.Read,
		Org:          orgs.FindByID,
		Insert:       users.Insert,
		InsertHuman:  users.InsertHuman,
		InsertMember: orgs.InsertMembership,
		UpdateHuman:  users.UpdateHuman,
		SetState:     users.SetState,
		Unlock:       users.Unlock,
		SoftDelete:   users.SoftDelete,
		InsertToken:  users.InsertToken,
		ClearMFA:     users.ClearMFA,
		TenantMember: tenants.FindMember,

		CountTenantOwners: tenants.CountOwners,

		// A person the tenant provisions is mirrored into the Scan Verifier, so a
		// later scan resolves to a real account. Both halves stay nil when the
		// integration is off, and nothing calls out.
		Enrol: diEnrol(diClient),
		SetDI: users.SetDIUserUUID,

		// The password of an administrative create meets the policy of the
		// organization it lands in. It is the same check the self-service change
		// runs, so the console policy is enforced wherever a password is chosen.
		CheckPassword: policySvc.Enforce,

		InTx:  tx,
		Audit: recorder,
		Log:   log,
	})

	orgSvc := organization.NewService(organization.Deps{
		List:        orgs.List,
		Find:        orgs.FindByID,
		Insert:      orgs.Insert,
		Rename:      orgs.Rename,
		Delete:      orgs.SoftDelete,
		Tenant:      tenants.FindByID,
		TenantRoles: tenants.MemberRoles,
		Memberships: orgs.ListMemberships,
		InTx:        tx,
		Audit:       recorder,
		Log:         log,
	})

	// The two rosters of a tenant are written by one service. The tenant owns
	// tenant_members and the organization owns organization_members, so each
	// write is the method of the domain that owns the table.
	memberSvc := organization.NewMemberService(organization.MemberDeps{
		ListTenantMembers:  tenants.ListMembers,
		ListOrgMembers:     orgs.ListMembers,
		SaveTenantMember:   tenants.SaveMember,
		SaveOrgMember:      orgs.SaveMembership,
		DeleteTenantMember: tenants.DeleteMember,
		DeleteOrgMember:    orgs.DeleteMembership,
		CountTenantOwners:  tenants.CountOwners,
		Org:                orgs.FindByID,
		TenantRoles:        tenants.MemberRoles,
		Memberships:        orgs.ListMemberships,
		InTx:               tx,
		Audit:              recorder,
		Log:                log,
	})

	projects := project.NewRepository(bdb, log)
	projectSvc := project.NewService(project.Deps{
		List:        projects.List,
		Find:        projects.FindByID,
		Insert:      projects.Insert,
		Update:      projects.Update,
		Delete:      projects.SoftDelete,
		TenantRoles: tenants.MemberRoles,
		Memberships: orgs.ListMemberships,
		InTx:        tx,
		Audit:       recorder,
		Log:         log,
	})

	apps := application.NewRepository(bdb, log)
	appSvc := application.NewService(application.Deps{
		List:         apps.List,
		Find:         apps.FindByID,
		Configs:      apps.Configs,
		Project:      projects.FindByID,
		Insert:       apps.Insert,
		InsertConfig: apps.InsertConfig,
		Update:       apps.Update,
		UpdateConfig: apps.UpdateConfig,
		SetSecret:    apps.SetSecret,
		Delete:       apps.SoftDelete,
		TenantRoles:  tenants.MemberRoles,
		Memberships:  orgs.ListMemberships,
		InTx:         tx,
		Audit:        recorder,
		Log:          log,
	})

	// The login sessions of a tenant, and the grants they fan out to. A revoke
	// hard deletes both, from the database and from the cache: a session and a
	// grant are consumed rows, and neither is recoverable once it ends. See
	// docs/adr/0002-session-storage.md.
	loginSessions := session.NewRepository(bdb, cipher, log)
	sessionSvc := session.NewAdminService(session.AdminDeps{
		List:             loginSessions.ListSessions,
		Revoke:           session.CachingRevoker(rdb, loginSessions.DeleteSession, log),
		RevokeUser:       session.CachingUserRevoker(rdb, loginSessions.DeleteUserSessions, log),
		RevokeGrants:     storage.DeleteGrantsByLoginSession,
		RevokeUserGrants: storage.DeleteGrantsBySubject,
		TenantRoles:      tenants.MemberRoles,
		InTx:             tx,
		Audit:            recorder,
		Log:              log,
	})

	grantSvc := oidc.NewGrantService(oidc.GrantDeps{
		List:        storage.ListGrants,
		TenantRoles: tenants.MemberRoles,
		Log:         log,
	})

	// The tenant record, the hostnames it answers on, and the bootstrap marker.
	// A domain remove flips the row to inactive: tenant_domains.domain is
	// globally unique, so a delete would free the host for another tenant and
	// the removal could not be undone.
	tenantSvc := tenant.NewAdminService(tenant.AdminDeps{
		Tenant:        tenants.FindByID,
		Domains:       tenants.ListAllDomains,
		FindDomain:    tenants.FindDomain,
		InsertDomain:  tenants.InsertDomain,
		RestoreDomain: tenants.RestoreDomain,
		RemoveDomain:  tenants.DeactivateDomain,
		Bootstrap:     tenants.ReadBootstrap,
		TenantRoles:   tenants.MemberRoles,
		InTx:          tx,
		Audit:         recorder,
		Log:           log,
	})

	// The protocol settings and the signing keys of the tenant. The key service
	// above serves the protocol, and this one serves the console: the read
	// carries the lifecycle columns and no key material.
	scopeRepo := oidc.NewScopeRepository(bdb, log)
	scopeSvc := oidc.NewScopeAdminService(oidc.ScopeAdminDeps{
		ListScopes:      scopeRepo.ListScopes,
		FindScope:       scopeRepo.FindScope,
		FindScopeByName: scopeRepo.FindScopeByName,

		InsertScope: scopeRepo.InsertScope,
		UpdateScope: scopeRepo.UpdateScope,
		DeleteScope: scopeRepo.DeleteScope,

		CountClientsWithScope: scopeRepo.CountClientsWithScope,

		ListMappers:  scopeRepo.ListMappers,
		FindMapper:   scopeRepo.FindMapper,
		CountMappers: scopeRepo.CountMappers,

		InsertMapper: scopeRepo.InsertMapper,
		UpdateMapper: scopeRepo.UpdateMapper,
		DeleteMapper: scopeRepo.DeleteMapper,

		TenantRoles: tenants.MemberRoles,
		InTx:        tx,
		Audit:       recorder,
		Log:         log,
	})

	// How the tenant sends mail, and the message each key renders. The relay is
	// tenant-wide, and a template resolves the organization override over the
	// tenant one over the message the gateway ships.
	notifications := notification.NewRepository(bdb, cipher, log)
	notificationSvc := notification.NewService(notification.Deps{
		FindSettings:   notifications.FindSettings,
		UpsertSettings: notifications.UpsertSettings,
		FindTemplate:   notifications.FindTemplate,
		UpsertTemplate: notifications.UpsertTemplate,
		RemoveTemplate: notifications.RemoveTemplate,
		Send:           notification.NewSender(log),
		// What a tenant that stores no row sends with. The configuration layer
		// carries the transport, the port, the TLS mode, and the timeout as
		// defaults, so this value is always complete.
		Defaults: notification.Settings{
			Transport:     notify.Transport,
			SMTPHost:      notify.SMTPHost,
			SMTPPort:      notify.SMTPPort,
			SMTPUsername:  notify.SMTPUsername,
			Password:      notify.SMTPPassword,
			FromAddress:   notify.FromAddress,
			FromName:      notify.FromName,
			TLSMode:       notify.TLSMode,
			SendTimeoutMS: int(notify.SendTimeout.Milliseconds()),
		},
		Org:         orgs.FindByID,
		TenantRoles: tenants.MemberRoles,
		Memberships: orgs.ListMemberships,
		InTx:        tx,
		Audit:       recorder,
		Log:         log,
	})

	// What every write above left behind. The feed is a read and nothing more:
	// a row of audit_events records a fact, so it is never updated and never
	// deleted.
	auditSvc := audit.NewService(audit.Deps{
		List:          audit.NewRepository(bdb, log).ListEvents,
		TenantManager: tenants.IsManager,
		Log:           log,
	})

	providerSvc := oidc.NewAdminService(oidc.AdminDeps{
		Provider:    providers.ReadByTenant,
		Update:      providers.Update,
		Keys:        keyRepo.ListKeys,
		TenantRoles: tenants.MemberRoles,
		InTx:        tx,
		Audit:       recorder,
		Log:         log,
	})

	group := app.Group(adminPrefix, tenantMW, bearer)
	tenant.AdminRoutes(group, tenant.NewAdminHandler(tenantSvc, tenantActor))
	oidc.AdminRoutes(group, oidc.NewAdminHandler(providerSvc, providerActor))
	oidc.ScopeAdminRoutes(group, oidc.NewScopeAdminHandler(scopeSvc, providerActor))
	user.AdminRoutes(group, user.NewHandler(svc))
	organization.AdminRoutes(group, organization.NewHandler(orgSvc))
	organization.MemberRoutes(group, organization.NewMemberHandler(memberSvc))
	project.AdminRoutes(group, project.NewHandler(projectSvc))
	application.AdminRoutes(group, application.NewHandler(appSvc))
	session.AdminRoutes(group, session.NewAdminHandler(sessionSvc))
	session.GrantRoutes(group, session.NewGrantHandler(grantSvc))
	authpolicy.AdminRoutes(group, authpolicy.NewHandler(policySvc))
	notification.AdminRoutes(group, notification.NewHandler(notificationSvc))
	audit.AdminRoutes(group, audit.NewHandler(auditSvc, auditActor),
		middlewares.Paginate(audit.SortKeys...))
}

// mountAccount builds the self-service account API the portal drives.
//
// The group carries the tenant lookup and then the bearer guard, the same way
// the admin management API does. The portal calls the issuer origin, so the host
// of the request already names the tenant.
//
// The guard admits only a token minted for the account resource identifier, so a
// token of the admin API never reaches these routes. There is no role gate:
// every route acts on the subject of the caller's own token and on nothing else.
//
// Every write runs in one transaction and records one audit event on it, so the
// group takes the same recorder and the same transaction runner the other stacks
// take.
func mountAccount(
	app *fiber.App, bdb *bun.DB, rdb cache.Client, cipher *crypto.Cipher,
	storage *oidc.StorageRepository, recorder *audit.Recorder,
	tenantMW fiber.Handler, tx db.TxRunner, log logger.Logger,
) {
	keys := oidc.NewKeyService(oidc.NewKeyRepository(bdb, log), cipher, log)
	bearer := middlewares.Bearer(keys.PublicKeySet, oidc.ResourceAccountAPI, log)

	// The password policy a new password is checked against. Enforce reads the
	// stored row of each level and nothing else, so this service is built with
	// the one dependency it needs. The console writes the policy, and that is
	// mounted on the admin API.
	policySvc := authpolicy.NewService(authpolicy.Deps{
		Find: authpolicy.NewRepository(bdb, log).Find,
		Log:  log,
	})

	// A person's own login sessions, and the grants each of them fanned out to.
	// The revoke hard deletes both, from the database and from the cache, the
	// same way the console force-logout does: a session and a grant are consumed
	// rows, and neither is recoverable once it ends.
	loginSessions := session.NewRepository(bdb, cipher, log)
	sessionSvc := session.NewAccountService(session.AccountDeps{
		List:         loginSessions.ListSessions,
		Revoke:       session.CachingRevoker(rdb, loginSessions.DeleteSession, log),
		RevokeOthers: session.CachingUserRevoker(rdb, loginSessions.DeleteUserSessions, log),
		RevokeGrants: storage.DeleteGrantsByLoginSession,
		InTx:         tx,
		Audit:        recorder,
		Log:          log,
	})

	// The profile and the password of the person the token names. A password
	// change ends every other login session of that person, so the service takes
	// the bulk revoke above: the write, the revoke, and the audit event land on
	// one transaction, and the transaction runner joins the one already open.
	users := user.NewRepository(bdb, log)
	accountSvc := user.NewAccountService(user.AccountDeps{
		UpdateProfile: users.UpdateProfile,
		Credential:    users.FindCredential,
		SetPassword:   users.SetPassword,
		CheckPassword: policySvc.Enforce,
		RevokeOthers: func(ctx context.Context, a user.Actor, exceptID string) error {
			_, err := sessionSvc.RevokeOthers(ctx, session.Actor(a), exceptID)
			return err
		},
		InTx:  tx,
		Audit: recorder,
		Log:   log,
	})

	// A person's own activity: the audit events where they were the actor. The
	// service narrows the read to the subject of the token, so this stack takes
	// the one repository read and nothing that decides who may read it.
	activitySvc := audit.NewAccountService(audit.AccountDeps{
		List: audit.NewRepository(bdb, log).ListEvents,
		Log:  log,
	})

	// The applications that hold the person's consent, and the disconnect that
	// takes one back. The withdraw and the grant delete land on one transaction,
	// so an application can never keep a refresh token of a consent that is
	// already withdrawn.
	consents := oidc.NewConsentRepository(bdb, log)
	connectionSvc := oidc.NewAccountService(oidc.AccountDeps{
		List:     consents.ListBySubject,
		Withdraw: consents.DeleteForSubject,
		Revoke:   storage.DeleteGrantsBySubjectClient,
		InTx:     tx,
		Audit:    recorder,
		Log:      log,
	})

	group := app.Group(accountPrefix, tenantMW, bearer)
	user.AccountRoutes(group, user.NewAccountHandler(accountSvc))
	oidc.AccountRoutes(group, oidc.NewAccountHandler(connectionSvc, accountActor))
	session.AccountRoutes(group, session.NewAccountHandler(sessionSvc))
	audit.AccountRoutes(group, audit.NewAccountHandler(activitySvc, auditActor),
		middlewares.Paginate(audit.SortKeys...))
}

// tenantActor, providerActor, and auditActor read the person behind one admin
// request.
//
// Every other domain reads the request for itself. These three cannot: the
// tenant middleware imports internal/tenant to resolve a host to its tenant and
// internal/oidc for the provider config of that tenant, and internal/tenant
// records its own writes through internal/audit. A handler in any of the three
// packages that imported the middleware would close an import cycle. The router
// imports everything, so it reads the request here and hands each domain a
// function value.
//
// Each one converts what middlewares.ActorFrom read. The three domain types are
// defined on internal/actor, so the conversion is a name change and nothing
// else. A read of the audit trail records nothing, and the service ignores the
// address and the agent it carries.
func tenantActor(c fiber.Ctx) tenant.Actor { return tenant.Actor(middlewares.ActorFrom(c)) }

func auditActor(c fiber.Ctx) audit.Actor { return audit.Actor(middlewares.ActorFrom(c)) }

func providerActor(c fiber.Ctx) oidc.AdminActor { return oidc.AdminActor(middlewares.ActorFrom(c)) }

func accountActor(c fiber.Ctx) oidc.AccountActor { return oidc.AccountActor(middlewares.ActorFrom(c)) }

// newSessionService builds the login session service both stacks share.
//
// The database is the source of truth, and Redis is the cache in front of it.
// See docs/adr/0002-session-storage.md.
func newSessionService(
	bdb *bun.DB, rdb cache.Client, cipher *crypto.Cipher, recorder *audit.Recorder,
	tx db.TxRunner, log logger.Logger,
) *session.Service {
	users := user.NewRepository(bdb, log)
	sessions := session.NewRepository(bdb, cipher, log)

	return session.NewService(session.Deps{
		Identity: identityFinder(users),
		// The one credential read of the user domain answers the organization
		// beside the hash. The sign-in needs the hash only.
		Credential: func(ctx context.Context, tenantID, userID string) (string, error) {
			row, err := users.FindCredential(ctx, tenantID, userID)
			return row.PasswordHash, err
		},
		Save:      session.CachingSaver(rdb, sessions.Save, cipher, log),
		Find:      session.CachedFinder(rdb, sessions.FindByTokenHash, cipher, log),
		Terminate: session.CachingTerminator(rdb, sessions.Terminate, log),
		InTx:      tx,
		Audit:     recorder,
		Log:       log,
	})
}

// identityFinder adapts the user repository to the session service, which knows
// a person as an id and an email and nothing more. The password step reads the
// repository directly, because its signature already matches.
func identityFinder(users *user.Repository) session.IdentityFinder {
	return func(ctx context.Context, tenantID, identifier string) (session.Identity, error) {
		row, err := users.FindByIdentifier(ctx, tenantID, identifier)
		if err != nil {
			return session.Identity{}, err
		}
		return session.Identity{UserID: row.ID, Email: row.Email}, nil
	}
}

// digitalIdentityOn reports whether the Digital Identity integration starts.
//
// The operator turns the whole integration on with one setting. A configuration
// that is on but incomplete does not start, and the reason is logged: a
// credential pair set on one half only is a typo, and a typo must never decide
// who gets in. Absent callback credentials do not start it either, because an
// endpoint whose success means "sign this person in" is never mounted open.
func digitalIdentityOn(cfg config.DIConfig, log logger.Logger) bool {
	if !cfg.Enabled {
		return false
	}
	if err := cfg.Validate(); err != nil {
		log.Error("digital identity: the integration did not start", logger.Err(err))
		return false
	}
	return true
}

// diEnrol adapts the outbound client to the dependency the user service takes.
// A nil client answers a nil function, which is how the service knows that this
// deployment runs no Scan Verifier.
func diEnrol(c *di.Client) user.DIEnroller {
	if c == nil {
		return nil
	}
	return c.EnrolUser
}

// mountCapabilities publishes what this deployment runs. The capability names the
// integration and not one flow, because it gates DI Enrolment as well as QR
// Login.
func mountCapabilities(app *fiber.App, digitalIdentity bool) {
	app.Get(capabilitiesPath, func(c fiber.Ctx) error {
		return response.OK(c, fiber.Map{"digital_identity": digitalIdentity})
	})
}

func healthCheckHandler(app *fiber.App) {
	app.Get(healthcheck.LivenessEndpoint, healthcheck.New())
	app.Get(healthcheck.ReadinessEndpoint, healthcheck.New())
	app.Get(healthcheck.StartupEndpoint, healthcheck.New())
}

func NotFoundHandler(c fiber.Ctx) error {
	return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
}
