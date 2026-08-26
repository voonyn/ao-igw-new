package tenant

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"alphaomega/identitygateway/internal/actor"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrForbidden reports that the person does not hold the role this step needs.
// A read needs a tenant manager, and a write needs the owner of the tenant.
var ErrForbidden = errors.New("the person does not administer this tenant")

// ErrDomainTaken reports that the host is already claimed. A host resolves to
// exactly one tenant, so the answer is the same whether this tenant holds it or
// another one does: it never reports which tenants exist.
var ErrDomainTaken = errors.New("the host is already mapped to a tenant")

// ErrPrimaryDomain reports an attempt to remove the primary host of a tenant.
// The issuer names that host, so removing it would refuse every token the tenant
// signed, including the one the operator is holding.
var ErrPrimaryDomain = errors.New("the primary domain cannot be removed")

// ErrNoBootstrapRecord reports a deployment whose schema was migrated but never
// bootstrapped. No tenant, no keys, and no provider config exist yet.
var ErrNoBootstrapRecord = errors.New("no bootstrap record")

// Actor is the person behind one administrative request. The IP and the agent
// travel to the audit trail, so the trail names where the change came from.
type Actor actor.Actor

// The reads and writes the administrative service composes its answers from.
// Each one is a function value, so the logic is testable without a database.
type (
	// TenantFinder reads one live tenant.
	TenantFinder func(ctx context.Context, tenantID string) (Tenant, error)

	// DomainLister reads every hostname of one tenant, the removed ones
	// included.
	DomainLister func(ctx context.Context, tenantID string) ([]Domain, error)

	// DomainFinder reads one hostname, whatever tenant holds it and whatever
	// state it is in. The host is globally unique, so the read takes no tenant.
	// A host nobody holds returns ErrDomainNotFound.
	DomainFinder func(ctx context.Context, domain string) (Domain, error)

	// DomainInserter maps one new host to a tenant.
	DomainInserter func(ctx context.Context, row Domain) error

	// DomainRestorer puts one removed host of a tenant back to work.
	DomainRestorer func(ctx context.Context, tenantID, domain string) error

	// DomainRemover flips one host of a tenant to inactive.
	DomainRemover func(ctx context.Context, tenantID, domain string) error

	// BootstrapReader reads the singleton bootstrap record of the deployment.
	BootstrapReader func(ctx context.Context) (Bootstrap, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// membership holds no role, which is not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)
)

// AdminDeps is the database side of the administrative service.
type AdminDeps struct {
	Tenant     TenantFinder
	Domains    DomainLister
	FindDomain DomainFinder

	InsertDomain  DomainInserter
	RestoreDomain DomainRestorer
	RemoveDomain  DomainRemover

	Bootstrap   BootstrapReader
	TenantRoles TenantRoleFinder

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AdminService serves the tenant record to the console, and the two writes that
// change the hostnames the gateway answers on.
type AdminService struct {
	deps AdminDeps
	log  logger.Logger
}

func NewAdminService(deps AdminDeps) *AdminService {
	return &AdminService{deps: deps, log: deps.Log}
}

// Read answers the tenant of the caller, with every hostname it holds.
func (s *AdminService) Read(ctx context.Context, a Actor) (View, error) {
	s.log.Debug("read the tenant",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, false, "read the tenant"); err != nil {
		return View{}, err
	}

	row, err := s.deps.Tenant(ctx, a.TenantID)
	if err != nil {
		return View{}, s.fail(a, "read the tenant", err)
	}
	domains, err := s.deps.Domains(ctx, a.TenantID)
	if err != nil {
		return View{}, s.fail(a, "read the domains of the tenant", err)
	}

	return view(row, domains), nil
}

// AddDomain maps one more host to the tenant.
//
// A host that this tenant removed earlier is restored instead of inserted. The
// row was never deleted, because a deleted row would free the globally unique
// host for another tenant, so the key it holds is the tenant's own.
//
// The write maps the host and nothing more. The host still has to resolve to
// this gateway in DNS and be forwarded by the reverse proxy before anything
// answers on it.
func (s *AdminService) AddDomain(ctx context.Context, a Actor, domain string) (DomainView, error) {
	host := bareHost(domain)
	s.log.Debug("add a tenant domain",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("domain", host), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, true, "add a tenant domain"); err != nil {
		return DomainView{}, err
	}

	row := Domain{
		Domain:     host,
		TenantID:   a.TenantID,
		IsVerified: true,
		State:      DomainStateActive,
	}
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		existing, err := s.deps.FindDomain(ctx, host)
		switch {
		case err == nil && existing.TenantID == a.TenantID && existing.State != DomainStateActive:
			// The tenant's own host, removed earlier. Put it back to work and
			// keep what the row already says about it.
			row.IsPrimary = existing.IsPrimary
			if err := s.deps.RestoreDomain(ctx, a.TenantID, host); err != nil {
				return err
			}
		case err == nil:
			return fmt.Errorf("%w: %s", ErrDomainTaken, host)
		case errors.Is(err, ErrDomainNotFound):
			if err := s.deps.InsertDomain(ctx, row); err != nil {
				return err
			}
		default:
			return err
		}

		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionDomainAdded,
			EntityType: audit.EntityTenantDomain,
			EntityID:   host,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
		})
	})
	if err != nil {
		if errors.Is(err, ErrDomainTaken) {
			return DomainView{}, err
		}
		return DomainView{}, s.fail(a, "add a tenant domain", err)
	}

	s.log.Info("added a tenant domain",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("domain", host))
	return domainView(row), nil
}

// RemoveDomain stops the tenant answering on one host.
//
// The row flips to inactive and stays. A delete would free the globally unique
// host for another tenant to claim, and the operator who removed it by mistake
// could not take it back.
func (s *AdminService) RemoveDomain(ctx context.Context, a Actor, domain string) error {
	host := bareHost(domain)
	s.log.Debug("remove a tenant domain",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("domain", host), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, true, "remove a tenant domain"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		existing, err := s.deps.FindDomain(ctx, host)
		if err != nil {
			return err
		}
		// A host of another tenant answers the way a host nobody holds answers.
		// The refusal never reports which tenant took it.
		if existing.TenantID != a.TenantID {
			return fmt.Errorf("%w: %s", ErrDomainNotFound, host)
		}
		if existing.IsPrimary {
			return fmt.Errorf("%w: %s", ErrPrimaryDomain, host)
		}

		if err := s.deps.RemoveDomain(ctx, a.TenantID, host); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionDomainRemoved,
			EntityType: audit.EntityTenantDomain,
			EntityID:   host,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
		})
	})
	if err != nil {
		if errors.Is(err, ErrDomainNotFound) || errors.Is(err, ErrPrimaryDomain) {
			return err
		}
		return s.fail(a, "remove a tenant domain", err)
	}

	s.log.Info("removed a tenant domain",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("domain", host))
	return nil
}

// ReadBootstrap answers the singleton record the bootstrap command wrote. The
// record is one row of the deployment and not of the tenant, so it names the
// tenant that the routine created.
func (s *AdminService) ReadBootstrap(ctx context.Context, a Actor) (BootstrapView, error) {
	s.log.Debug("read the bootstrap record",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, false, "read the bootstrap record"); err != nil {
		return BootstrapView{}, err
	}

	row, err := s.deps.Bootstrap(ctx)
	if errors.Is(err, ErrNoBootstrapRecord) {
		return BootstrapView{}, err
	}
	if err != nil {
		return BootstrapView{}, s.fail(a, "read the bootstrap record", err)
	}

	return BootstrapView{
		ID:        row.ID,
		TenantID:  row.TenantID,
		Version:   row.Version,
		AppliedAt: row.AppliedAt,
		Artifacts: []ArtifactView{},
	}, nil
}

// authorize is the gate of every route of this service.
//
// A read needs a tenant manager: the record names every host the gateway
// answers on. A write needs the owner: a domain maps a globally unique host, and
// the primary host is what every token of the tenant is issued from.
func (s *AdminService) authorize(ctx context.Context, a Actor, write bool, what string) error {
	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}

	if slices.Contains(roles, RoleIAMOwner) ||
		(!write && slices.Contains(roles, RoleIAMAdmin)) {
		return nil
	}

	s.log.Warn("refused a person who does not hold the role",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *AdminService) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}

// bareHost is how a host is stored and compared. The lookup that resolves a
// request to its tenant lowercases the request host, so the stored value is
// lowercased too and the two always meet.
func bareHost(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

func view(row Tenant, domains []Domain) View {
	out := View{
		ID:           row.ID,
		Name:         row.Name,
		State:        row.State,
		DefaultOrgID: row.DefaultOrgID,
		Created:      row.CreatedAt,
		Domains:      make([]DomainView, 0, len(domains)),
	}
	for _, d := range domains {
		out.Domains = append(out.Domains, domainView(d))
	}
	return out
}

func domainView(row Domain) DomainView {
	return DomainView{
		Domain:     row.Domain,
		IsPrimary:  row.IsPrimary,
		IsVerified: row.IsVerified,
		State:      row.State,
	}
}
