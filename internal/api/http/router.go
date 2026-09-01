package http

import (
	"context"
	"errors"
	"fmt"
	"slices"

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
	"alphaomega/identitygateway/internal/identityprovider"
	"alphaomega/identitygateway/internal/notification"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/passkey"
	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/project"
	"alphaomega/identitygateway/internal/qrlogin"
	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/tenant"
	"alphaomega/identitygateway/internal/totp"
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

// mfaSuffix is where the sign-in front end reaches the second-factor steps,
// inside the login group. It carries the same credential as the other login
// steps.
const mfaSuffix = "/mfa"

// qrLoginSuffix is where the sign-in front end reaches the two browser steps of
// QR Login, inside the login group. It carries the same credential as the other
// login steps.
const qrLoginSuffix = "/qr"

// qrLoginPrefix is the full path of those two steps.
const qrLoginPrefix = loginPrefix + qrLoginSuffix

// qrCallbackPath is where the Scan Verifier pushes the result of a scan. It sits
// outside every group: the push carries its own credential, and its host names no
// tenant. See docs/adr/0008-scan-verifier-push-callback.md.
const qrCallbackPath = "/api/v1/di/callback"

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

	// The TOTP factor of every person. It is read at the password step, to name
	// the factor a person still owes, and written by the enrolment steps below.
	factors := totp.NewRepository(bdb, log)

	// What a person still owes after the password. One function answers it, and
	// it is built here so that every reader takes the same function value. ADR
	// 0011 fixes that: two copies of an authentication predicate drift, and a
	// drifted predicate is a security defect.
	//
	// Three places read it now. The password answer names the route forward, the
	// finalize step refuses a session that owes a Factor, and the sign-in
	// enrolment guard of both Second Factor modules refuses a person the steps
	// name a challenge for.
	steps := pendingSteps(user.NewRepository(bdb, log), factors, bdb, log)

	// The login session service serves both stacks. The login UI drives it, and
	// an RP-initiated logout ends a session through it, so it is built once here
	// and handed to each stack.
	sessions := newSessionService(bdb, rdb, cipher, recorder, steps, tx.RunInTx, log)

	mountOIDCRoutes(app, cfg, bdb, storage, scopes, claims, recorder, cipher, sessions, tenantMW, tx.RunInTx, log)

	// The login group carries the credential of the sign-in front end and the
	// tenant lookup. QR Login mounts inside it, so both run once per request.
	loginGroup := app.Group(loginPrefix, middlewares.LoginPAT(cfg.Auth.LoginPATs(), log), tenantMW)
	mountLogin(loginGroup, cfg, bdb, cipher, storage, scopes, recorder, sessions, tx.RunInTx, log)
	// The second-factor service serves both stacks. The sign-in drives its two
	// enrolment steps and its challenge, and the portal drives the same enrolment
	// under an access token, so one build is handed to each.
	factorSvc := mountMFA(
		loginGroup, cfg, bdb, rdb, cipher, factors, steps, recorder, sessions, tx.RunInTx, log)
	// How this deployment sends mail. Both stacks send: the console configures
	// the templates, and the account stack tells a person that a Factor changed
	// on their account. One build means one set of settings and one set of
	// templates behind both.
	notificationSvc := newNotificationService(bdb, cipher, cfg.Notification, recorder, tx.RunInTx, log)

	mountAdmin(app, bdb, rdb, cipher, storage, factors, recorder, notificationSvc, diClient, tenantMW, tx.RunInTx, log)
	mountAccount(app, cfg, bdb, rdb, cipher, storage, recorder, factorSvc, notificationSvc, tenantMW, tx.RunInTx, log)

	// QR Login exists only where a Scan Verifier does. With the integration off,
	// none of the three routes are mounted, so the sign-in front end reads the
	// capability and offers no dead option.
	if digitalIdentity {
		mountQRLogin(app, loginGroup, cfg.DI, bdb, diClient, sessions, recorder, log)
	}

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
		ACRPrefix:  cfg.OIDC.ACRPrefix,
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

// mountLogin builds the login stack the login UI drives. The caller mounts the
// PAT check and the tenant lookup on the group, because only the login UI
// reaches it.
func mountLogin(
	group fiber.Router, cfg *config.Config, bdb *bun.DB, cipher *crypto.Cipher,
	storage *oidc.StorageRepository, scopes *oidc.ScopeService, recorder *audit.Recorder,
	svc *session.Service, tx db.TxRunner, log logger.Logger,
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
		ACRPrefix:  cfg.OIDC.ACRPrefix,
		Find:       storage.FindSession,
		Save:       storage.SaveSession,
		Decide:     consent.Decide,
		Approve:    consent.Approve,
		Deny:       consent.Deny,
		Log:        log,
	})

	session.Routes(group, session.NewHandler(svc, complete, scopes.Describe, log))
}

// mountMFA builds the second-factor steps of the sign-in: the two enrolment
// steps, and the challenge a person who holds a factor answers.
//
// They mount inside the login group, so its credential and its tenant lookup run
// once each. A group of their own would match the same prefix and run both a
// second time.
//
// The TOTP module imports neither the user domain nor the login session domain,
// so every crossing between them is composed here. That is the router's stated
// job, and it is what keeps the login session domain, which already imports the
// user domain, out of an import cycle.
//
// It answers the service it built. The portal drives the same enrolment under an
// access token, and a second build would give that path its own dependencies to
// drift from these.
func mountMFA(
	loginGroup fiber.Router, cfg *config.Config, bdb *bun.DB, rdb cache.Client,
	cipher *crypto.Cipher, factors *totp.Repository, steps session.PendingSteps,
	recorder *audit.Recorder, sessions *session.Service, tx db.TxRunner, log logger.Logger,
) *totp.Service {
	users := user.NewRepository(bdb, log)

	// The password check the two destructive portal addresses demand. It reads
	// the stored credential of one person and nothing else, so it is built with
	// that one dependency.
	passwords := user.NewAccountService(user.AccountDeps{
		Credential: users.FindCredential,
		Log:        log,
	})

	// A sign-in enrols a Second Factor only for a person who holds none. Each
	// module refuses its own enrolment start with it, so a person who holds one
	// Factor cannot answer the challenge they owe by adding the other one.
	//
	// It reads the steps and never the two tables. A person the steps name a
	// challenge for is a person who holds a Factor, so this is the same predicate
	// the password answer and the finalize gate read. A second pair of reads here
	// is the drift ADR 0011 refuses.
	//
	// The reads inside are logged there and nowhere else, the way pendingSteps
	// says. This adds no log line of its own.
	holdsFactor := func(ctx context.Context, tenantID, userID string) (bool, error) {
		owed, err := steps(ctx, tenantID, userID)
		if err != nil {
			return false, err
		}
		return slices.ContainsFunc(owed, session.IsChallengeStep), nil
	}

	svc := totp.NewService(totp.Deps{
		FindSession: func(ctx context.Context, tenantID, token string) (totp.Principal, error) {
			// Find, and not Resolve: the module decides what an unfinished
			// session may do, and it refuses one that proved no password.
			live, err := sessions.Find(ctx, tenantID, token)
			if err != nil {
				return totp.Principal{}, err
			}
			_, proved := live.Factors[session.FactorPassword]
			return totp.Principal{
				SessionID:      live.ID,
				UserID:         live.UserID,
				PasswordProved: proved,
				IP:             live.IP,
				UserAgent:      live.UserAgent,
			}, nil
		},
		// The factor name is the login session domain's to spell, so it is named
		// here and nowhere inside the TOTP module.
		CompleteSession: func(ctx context.Context, tenantID, token, userID string) (string, error) {
			upgraded, err := sessions.Complete(ctx, tenantID, token, userID, session.FactorOTP)
			return upgraded.Token, err
		},
		// What an Authenticator prints beside the code. The email address is what
		// a person recognises, and the username stands in for an account that
		// holds no email.
		Account: func(ctx context.Context, tenantID, userID string) (string, error) {
			row, err := users.FindByID(ctx, tenantID, userID)
			if err != nil {
				return "", err
			}
			if row.Email != "" {
				return row.Email, nil
			}
			return row.Username, nil
		},

		Find:               factors.Find,
		SavePending:        factors.SavePending,
		Activate:           factors.Activate,
		SaveRecoveryCodes:  factors.ReplaceRecoveryCodes,
		CountRecoveryCodes: factors.CountRecoveryCodes,
		SpendStep:          factors.SpendStep,
		RedeemRecoveryCode: factors.RedeemRecoveryCode,
		ClearFactor:        factors.Clear,

		// The proof the two destructive portal addresses demand. It is the one
		// the password change runs, so a person reads one refusal wherever the
		// portal asks for a password, and this module imports neither the user
		// domain nor the password hashing.
		//
		// The service below is built with the one dependency that check needs.
		// The account stack builds its own with the writes it needs too, and a
		// second copy of the check is what this avoids.
		VerifyPassword: func(ctx context.Context, tenantID, userID, plain string) error {
			return passwords.VerifyPassword(ctx,
				user.Actor{TenantID: tenantID, UserID: userID}, plain)
		},

		// The two caps on code guessing. The per-session count and the audit row
		// belong to the login session domain, and the per-person budget is the
		// sliding window Redis keeps.
		FailCode: sessions.FailSecondFactor,
		Allow:    rdb.AllowInWindow,

		// The held-Factor guard of the two sign-in enrolment steps. The portal
		// enrolment reads nothing of the kind: it is where a person adds a second
		// kind of Factor beside the one they hold.
		HoldsFactor: holdsFactor,

		Cipher: cipher,
		InTx:   tx,
		Audit:  recorder,
		Log:    log,
	})

	// One group holds both Second Factors, so the credential of the front end,
	// the tenant lookup, and the tenant guard each run once per request.
	mfaGroup := loginGroup.Group(mfaSuffix)
	totp.LoginRoutes(mfaGroup, totp.NewHandler(svc))

	// The Passkey half of the sign-in: the challenge a holder answers, and the
	// enrolment a person the MFA Requirement governs runs instead. It mounts
	// beside the TOTP routes, so the two Second Factors sit side by side.
	//
	// The module imports neither the user domain nor the login session domain,
	// so both crossings are composed here, the way the TOTP crossings above are.
	passkeys := passkey.NewRepository(bdb, log)
	deps := passkeyCeremony(cfg, passkeys, tenant.NewRepository(bdb, log), rdb, users,
		recorder, tx, log)
	deps.Touch = passkeys.Touch

	// The three writes the enrolment needs. A registration inserts a new
	// credential id, or takes back the row of a device somebody removed, and the
	// read is what decides between them.
	//
	// No notification is wired. The person is at the keyboard signing in, so a
	// message telling them a Factor was added says nothing they do not see, and
	// the TOTP enrolment beside it sends none either.
	deps.Insert = passkeys.Insert
	deps.Find = passkeys.FindByCredential
	deps.Revive = passkeys.Revive

	// The same guard the TOTP enrolment above runs, on the same reads. One rule
	// stated once, so the two enrolment routes cannot drift apart.
	deps.HoldsFactor = holdsFactor

	deps.FindSession = func(ctx context.Context, tenantID, token string) (passkey.Principal, error) {
		// Find, and not Resolve: the module decides what an unfinished session
		// may do, and it refuses one that proved no password.
		live, err := sessions.Find(ctx, tenantID, token)
		if err != nil {
			return passkey.Principal{}, err
		}
		_, proved := live.Factors[session.FactorPassword]
		return passkey.Principal{
			UserID:         live.UserID,
			IP:             live.IP,
			UserAgent:      live.UserAgent,
			SessionID:      live.ID,
			PasswordProved: proved,
		}, nil
	}
	// The factor name is the login session domain's to spell, so it is named
	// here and nowhere inside the passkey module. ADR 0012 fixes the value.
	deps.CompleteSession = func(ctx context.Context, tenantID, token, userID string) (string, error) {
		upgraded, err := sessions.Complete(ctx, tenantID, token, userID, session.FactorPasskey)
		return upgraded.Token, err
	}
	passkey.LoginRoutes(mfaGroup, passkey.NewHandler(passkey.NewService(deps)))

	return svc
}

// passkeyCeremony is the half of the passkey dependencies both ceremonies share:
// who the person is, the Passkeys they hold, the origins a ceremony may run
// from, the RP ID override, and the challenge store. The store holds the two
// start budgets of the module too, and the module owns both of them.
//
// One builder holds them because the sign-in and the portal must derive the same
// RP ID from the same host and keep the same origins. Two copies of that
// resolution would let a Passkey register under a relying party no sign-in
// answers.
//
// Each caller fills the rest: the portal adds the writes and the password proof,
// and the sign-in adds the two login session crossings and the write-back.
func passkeyCeremony(
	cfg *config.Config, passkeys *passkey.Repository, tenants *tenant.Repository,
	rdb cache.Client, users *user.Repository,
	recorder *audit.Recorder, tx db.TxRunner, log logger.Logger,
) passkey.Deps {
	return passkey.Deps{
		// What the library prints beside the prompt. It never reaches an
		// authenticator screen here, because a Passkey is a Second Factor and
		// the person already typed an identifier, but the library demands it.
		Account: func(ctx context.Context, tenantID, userID string) (string, error) {
			row, err := users.FindByID(ctx, tenantID, userID)
			if err != nil {
				return "", err
			}
			if row.Email != "" {
				return row.Email, nil
			}
			return row.Username, nil
		},

		List: passkeys.List,

		// Every origin a ceremony of this tenant may run from: the hosts the
		// tenant serves, and the front ends of the deployment. The library
		// refuses to start with an empty list, so a tenant that serves no
		// verified host and a deployment that named no front end run no ceremony.
		Origins: func(ctx context.Context, tenantID string) ([]string, error) {
			rows, err := tenants.ListDomains(ctx, tenantID)
			if err != nil {
				return nil, err
			}
			return webAuthnOrigins(rows, cfg.OIDC.WebAuthnOrigins), nil
		},

		RPIDOverride: cfg.OIDC.WebAuthnRPID,
		Ceremony:     rdb,

		InTx:  tx,
		Audit: recorder,
		Log:   log,
	}
}

// mountQRLogin builds the three routes that turn a scan into a sign-in.
//
// The two browser steps mount beside the other login steps, behind the credential
// of the sign-in front end and the tenant lookup of the host. The push callback
// mounts outside both: it reaches one fixed address that names no tenant, and it
// carries a credential of its own.
//
// The callback credential is a different value from the login credential and from
// the credentials this deployment presents to the Scan Verifier. A shared value
// would turn one compromise into the power to sign in as anybody.
func mountQRLogin(
	app *fiber.App, loginGroup fiber.Router, diCfg config.DIConfig, bdb *bun.DB,
	diClient *di.Client, sessions *session.Service, recorder *audit.Recorder,
	log logger.Logger,
) {
	users := user.NewRepository(bdb, log)
	transactions := qrlogin.NewRepository(bdb, log)

	svc := qrlogin.NewService(qrlogin.Deps{
		Start: diClient.InitializeVPTransaction,

		Insert:        transactions.Insert,
		ByVerifierRef: transactions.FindByVerifierRef,
		ByLoginSess:   transactions.FindByLoginSession,
		Consume:       transactions.Consume,
		SetResult:     transactions.SetResult,

		OpenSession:     sessions.Open,
		FindSession:     sessions.Find,
		CompleteSession: sessions.Complete,

		// The scan resolves against the username, which is the key the Scan
		// Verifier holds a person by. A read that also matched an email address
		// would sign in a person the scan did not name.
		User: func(ctx context.Context, tenantID, username string) (string, error) {
			row, err := users.FindByUsername(ctx, tenantID, username)
			return row.ID, err
		},

		Audit: recorder,
		Log:   log,
	})

	handler := qrlogin.NewHandler(svc)
	// The two browser steps mount inside the login group, so its credential and
	// its tenant lookup run once each. A group of their own would match the same
	// prefix and run both a second time.
	qrlogin.Routes(loginGroup.Group(qrLoginSuffix), handler)
	qrlogin.CallbackRoute(app, qrCallbackPath,
		middlewares.StaticBasic(diCfg.CallbackClientID, diCfg.CallbackClientSecret, log),
		handler)

	log.Info("qr login mounted",
		logger.String("prefix", qrLoginPrefix),
		logger.String("callback_path", qrCallbackPath))
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
	storage *oidc.StorageRepository, factors *totp.Repository, recorder *audit.Recorder,
	notificationSvc *notification.Service, diClient *di.Client, tenantMW fiber.Handler,
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
		ClearMFA:     clearSecondFactors(factors.Clear, users.ClearPasskeys),
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

	// The Passkeys of one person, as an operator reads and revokes them. The
	// module imports neither the user domain nor the login session domain, so the
	// role check is composed here, the way the account mount composes the
	// password proof of the self-service removal.
	//
	// Two calls and no more: nothing here registers a Passkey for another person.
	// A Factor belongs to whoever holds the device, so the ceremony runs on the
	// portal alone and no ceremony dependency is wired.
	passkeys := passkey.NewRepository(bdb, log)
	//
	// Two gates and not one. The list runs the read gate every other card of
	// that screen runs, so an operator who reads the account record reads the
	// devices on it. The revoke runs the write gate, which narrows to the
	// organization of the account.
	passkeyAdminSvc := passkey.NewAdminService(passkey.AdminDeps{
		AuthorizeRead: func(ctx context.Context, tenantID, actorID, _ string) error {
			return svc.AuthorizeRead(ctx, user.Actor{TenantID: tenantID, UserID: actorID})
		},
		AuthorizeWrite: func(ctx context.Context, tenantID, actorID, userID string) error {
			return svc.AuthorizeWrite(ctx,
				user.Actor{TenantID: tenantID, UserID: actorID}, userID,
				"revoke a passkey of a user")
		},
		List:   passkeys.List,
		Delete: passkeys.Delete,
		InTx:   tx,
		Audit:  recorder,
		Log:    log,
	})

	// The directories a tenant registers, the domains each one claims, and the
	// Identity Link that ties one directory account to one person. The repository
	// holds the cipher, so the bind password is sealed at rest and no layer above
	// it ever holds the ciphertext.
	idps := identityprovider.NewRepository(bdb, cipher, log)
	idpSvc := identityprovider.NewService(identityprovider.Deps{
		List:    idps.List,
		Find:    idps.FindByID,
		Insert:  idps.Insert,
		Update:  idps.Update,
		Delete:  idps.Delete,
		Domains: idps.Domains,
		Claim:   idps.Claim,

		Links:      idps.Links,
		DeleteLink: idps.DeleteLink,

		Org: orgs.FindByID,
		// The package imports neither the user domain nor the login session
		// domain, so the crossing is a function value and the miss is translated
		// here into the sentinel that package declares.
		UserOrg: func(ctx context.Context, tenantID, userID string) (string, error) {
			row, err := users.FindByID(ctx, tenantID, userID)
			if errors.Is(err, user.ErrNotFound) {
				return "", fmt.Errorf("%w: tenant %s, user %s",
					identityprovider.ErrUserNotFound, tenantID, userID)
			}
			if err != nil {
				return "", err
			}
			return row.OrgID, nil
		},
		TenantRoles: tenants.MemberRoles,
		Memberships: orgs.ListMemberships,

		// The budget of the connection test. It is an outbound call into a
		// customer network that any console user of the tenant drives, so the
		// counter lives in Redis alone and a cache failure refuses the test.
		Allow: rdb.AllowInWindow,

		InTx:  tx,
		Audit: recorder,
		Log:   log,
	})

	group := app.Group(adminPrefix, tenantMW, bearer)
	tenant.AdminRoutes(group, tenant.NewAdminHandler(tenantSvc, tenantActor))
	oidc.AdminRoutes(group, oidc.NewAdminHandler(providerSvc, providerActor))
	oidc.ScopeAdminRoutes(group, oidc.NewScopeAdminHandler(scopeSvc, providerActor))
	user.AdminRoutes(group, user.NewHandler(svc))
	passkey.AdminRoutes(group, passkey.NewAdminHandler(passkeyAdminSvc))
	organization.AdminRoutes(group, organization.NewHandler(orgSvc))
	organization.MemberRoutes(group, organization.NewMemberHandler(memberSvc))
	project.AdminRoutes(group, project.NewHandler(projectSvc))
	application.AdminRoutes(group, application.NewHandler(appSvc))
	session.AdminRoutes(group, session.NewAdminHandler(sessionSvc))
	session.GrantRoutes(group, session.NewGrantHandler(grantSvc))
	authpolicy.AdminRoutes(group, authpolicy.NewHandler(policySvc))
	notification.AdminRoutes(group, notification.NewHandler(notificationSvc))
	identityprovider.AdminRoutes(group, identityprovider.NewHandler(idpSvc))
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
	app *fiber.App, cfg *config.Config, bdb *bun.DB, rdb cache.Client, cipher *crypto.Cipher,
	storage *oidc.StorageRepository, recorder *audit.Recorder, factorSvc *totp.Service,
	notificationSvc *notification.Service, tenantMW fiber.Handler, tx db.TxRunner,
	log logger.Logger,
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

	// The Passkeys of the person the token names. The module imports neither the
	// user domain nor the login session domain, so every crossing between them is
	// composed here, the way the second-factor mount composes the TOTP module.
	//
	// The ceremony store is Redis and nothing else. No table holds a challenge,
	// and a cache failure refuses the ceremony. See
	// docs/adr/0002-session-storage.md.
	passkeys := passkey.NewRepository(bdb, log)
	passkeyDeps := passkeyCeremony(cfg, passkeys, tenant.NewRepository(bdb, log), rdb, users,
		recorder, tx, log)
	passkeyDeps.Insert = passkeys.Insert
	passkeyDeps.Find = passkeys.FindByCredential
	passkeyDeps.Revive = passkeys.Revive
	passkeyDeps.Rename = passkeys.Rename
	passkeyDeps.Delete = passkeys.Delete

	// The proof the removal demands. It is the check the TOTP removal and the
	// password change both run, so a person reads one refusal wherever the portal
	// asks for a password, and this module imports neither the user domain nor
	// the password hashing.
	passkeyDeps.VerifyPassword = func(ctx context.Context, tenantID, userID, plain string) error {
		return accountSvc.VerifyPassword(ctx,
			user.Actor{TenantID: tenantID, UserID: userID}, plain)
	}

	// What tells the person that a Factor was added. It sends to the email
	// address of the account, and an account that holds none is told nothing: a
	// machine account has no person to warn.
	passkeyDeps.Notify = func(ctx context.Context, tenantID, userID, _ string) error {
		row, err := users.FindByID(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if row.Email == "" {
			return nil
		}
		name := row.DisplayName
		if name == "" {
			name = row.Email
		}
		return notificationSvc.Notify(ctx, tenantID,
			notification.KeyPasskeyRegistered, row.Email,
			notification.Vars{DisplayName: name})
	}

	passkeySvc := passkey.NewService(passkeyDeps)

	group := app.Group(accountPrefix, tenantMW, bearer)
	user.AccountRoutes(group, user.NewAccountHandler(accountSvc))
	passkey.AccountRoutes(group, passkey.NewAccountHandler(passkeySvc))
	oidc.AccountRoutes(group, oidc.NewAccountHandler(connectionSvc, accountActor))
	session.AccountRoutes(group, session.NewAccountHandler(sessionSvc))
	totp.AccountRoutes(group, totp.NewAccountHandler(factorSvc))
	audit.AccountRoutes(group, audit.NewAccountHandler(activitySvc, auditActor),
		middlewares.Paginate(audit.SortKeys...))
}

// newNotificationService builds the mail service both stacks share.
//
// The relay is tenant-wide, and a template resolves the organization override
// over the tenant one over the message the gateway ships. The console
// configures all three, and the account stack sends through the same resolution,
// so a tenant that reworded a message sends the words it chose wherever the
// message comes from.
//
// It builds its own organization and tenant repositories. Both are stateless
// query holders, and the two authorization reads below are all this service
// takes from them.
func newNotificationService(
	bdb *bun.DB, cipher *crypto.Cipher, notify config.NotificationConfig,
	recorder *audit.Recorder, tx db.TxRunner, log logger.Logger,
) *notification.Service {
	orgs := organization.NewRepository(bdb, log)
	tenants := tenant.NewRepository(bdb, log)
	notifications := notification.NewRepository(bdb, cipher, log)

	return notification.NewService(notification.Deps{
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
}

// webAuthnOrigins names every origin a passkey ceremony of one tenant may run
// from.
//
// The tenant's own hosts come from its domain rows, so a tenant that adds a host
// can register a Passkey on it with no deployment change. Each one is https:
// the sign-in serves nothing else, and a browser runs no ceremony over http
// anyway, except on localhost.
//
// The deployment origins are the portal and the console. They are whole origins,
// scheme and port included, because those front ends are not tenant hosts and a
// development one runs on http.
//
// This list is what the ceremony may run from, not what it will run from. The
// passkey module keeps only the origins the tenant's RP ID covers, because a
// device binds to that RP ID and a Passkey created anywhere else answers no
// sign-in of this tenant.
func webAuthnOrigins(rows []tenant.Domain, deployment []string) []string {
	origins := make([]string, 0, len(rows)+len(deployment))
	origins = append(origins, deployment...)
	for _, row := range rows {
		origins = append(origins, "https://"+row.Domain)
	}
	return origins
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
	steps session.PendingSteps, tx db.TxRunner, log logger.Logger,
) *session.Service {
	users := user.NewRepository(bdb, log)
	sessions := session.NewRepository(bdb, cipher, log)

	// Which Identity Provider proves this sign-in. The session domain imports
	// neither the provider domain nor the four reads that answer the question,
	// so the crossing is one function value composed here.
	//
	// The resolver is built beside the session and not beside the console
	// service, because resolution runs on the sign-in path, where there is no
	// actor, no audit row, and no transaction.
	idps := identityprovider.NewRepository(bdb, cipher, log)
	resolver := identityprovider.NewResolver(identityprovider.ResolverDeps{
		DomainOwner: idps.FindByDomain,
		Linked:      idps.LinkedProviders,
		Active:      idps.ActiveIDs,
		Held:        users.HoldsIdentifier,
		Log:         log,
	})

	return session.NewService(session.Deps{
		Identity: identityFinder(users),
		Provider: resolver.Resolve,
		Steps:    steps,
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

// pendingSteps names the Pending Steps a person still owes after the password
// step.
//
// A person who holds a Second Factor is sent to the challenge of every Factor
// they hold, and a person the requirement governs who holds none is sent to
// enrolment.
//
// The Passkey step comes first. It is the faster Factor and the stronger one, so
// the sign-in front end renders it and offers the rest as another method.
//
// It reads through four domains, so it is composed here: the person names the
// organization, the organization resolves the MFA Requirement over the tenant
// default, and the TOTP and passkey modules each answer whether the person holds
// that Factor.
//
// Moving it into internal/authpolicy was weighed and refused. No cycle blocks the
// move, but that package is a policy leaf today, and Service.MFARequired is shaped
// as a function value so that the login stack imports nothing from it. The move
// would make authpolicy import user, totp and session to gain nothing at runtime.
//
// The requirement resolves through both policy levels, the way the password
// policy already does. A read of the tenant row alone would make every
// organization override silently do nothing while the console reports it as set.
//
// Each Factor is read from the module that owns it. The derived second-factor
// column on the user list counts both in one flag, and a step list built from it
// could not say which challenge a person can actually answer.
//
// One function answers the step signal, so the signal and the gate that enforces
// it can never disagree. Two copies of an authentication predicate drift, and a
// drifted predicate is a security defect.
func pendingSteps(
	users *user.Repository, factors *totp.Repository, bdb *bun.DB, log logger.Logger,
) session.PendingSteps {
	passkeys := passkey.NewRepository(bdb, log)

	// Only the stored row of each level is read here, so the policy service is
	// built with the one dependency it needs. The console writes the policy, and
	// that is mounted on the admin API.
	policies := authpolicy.NewService(authpolicy.Deps{
		Find: authpolicy.NewRepository(bdb, log).Find,
		Log:  log,
	})

	return func(ctx context.Context, tenantID, userID string) ([]string, error) {
		// A session that names nobody owes nothing. The password step refuses it
		// on the decoy hash, so this is never reached with a match.
		if userID == "" {
			return nil, nil
		}

		// A Factor the person holds is always challenged, whatever the policy
		// says, so both reads come first and the requirement is never consulted.
		// A person who chose to protect their account keeps that protection on
		// the day an administrator clears the flag.
		// The reads below are logged here and nowhere else. The caller takes this
		// as an opaque function value and cannot classify what it answers, so
		// this is the last layer that can name the tenant and the person the read
		// was for. MFARequired logs its own failure, which is why the read under
		// it is returned raw.
		key, err := passkeys.HasAny(ctx, tenantID, userID)
		if err != nil {
			log.Error("read the passkeys to resolve the pending steps",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", userID), logger.Err(err))
			return nil, err
		}
		held, err := factors.HasActiveFactor(ctx, tenantID, userID)
		if err != nil {
			log.Error("read the active second factor to resolve the pending steps",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", userID), logger.Err(err))
			return nil, err
		}

		// The Passkey first: it is the faster Factor, and the front end renders
		// the first step and offers the rest as another method. A person who
		// holds both is offered both, and proves one of them.
		steps := make([]string, 0, 2)
		if key {
			steps = append(steps, session.StepChallengePasskey)
		}
		if held {
			steps = append(steps, session.StepChallengeOTP)
		}
		if len(steps) > 0 {
			return steps, nil
		}

		row, err := users.FindByID(ctx, tenantID, userID)
		if err != nil {
			log.Error("read the account to resolve the pending steps",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", userID), logger.Err(err))
			return nil, err
		}
		required, err := policies.MFARequired(ctx, tenantID, row.OrgID)
		if err != nil {
			return nil, err
		}
		if !required {
			return nil, nil
		}

		// Both enrolments, the Passkey first. The person picks one, and the
		// screen renders both at once: a device with no authenticator must never
		// dead-end, so the Authenticator stays beside the Passkey at all times.
		//
		// The order is the same preference the challenge steps carry. It names
		// which Factor the screen offers first, and nothing more: the front end
		// renders both, and the finalize gate reads whichever one the person
		// enrolled.
		return []string{session.StepEnrolPasskey, session.StepEnrolOTP}, nil
	}
}

// clearSecondFactors composes a full second-factor reset from the two modules
// that own the tables: the TOTP module destroys the secret and the recovery
// codes, and the user module removes the passkeys.
//
// The composition sits here, and not in either module, because neither may
// import the other. The login session domain already imports the user domain,
// so a TOTP module that imported it would close a cycle.
//
// Both halves run on the caller's transaction, so a reset lands whole or not at
// all. A failing first half stops the second, and the caller rolls both back.
func clearSecondFactors(factors, passkeys user.MFAClearer) user.MFAClearer {
	return func(ctx context.Context, tenantID, userID string) error {
		if err := factors(ctx, tenantID, userID); err != nil {
			return err
		}
		return passkeys(ctx, tenantID, userID)
	}
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
		return response.OK(c, fiber.Map{"digitalIdentity": digitalIdentity})
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
