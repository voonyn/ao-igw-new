// Package tenant holds the tenant domain: the tenants themselves and the
// hostnames that belong to them.
package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrDomainNotFound reports that no live tenant domain carries the hostname.
// The request stops there, because no tenant can serve it.
var ErrDomainNotFound = errors.New("tenant domain not found")

// ErrTenantNotFound reports that no live tenant carries the id.
var ErrTenantNotFound = errors.New("tenant not found")

// ErrMemberNotFound reports that no live tenant membership carries the person.
// A revoke of a membership nobody holds answers it.
var ErrMemberNotFound = errors.New("tenant member not found")

// The two states of tenant_domains.state. An inactive domain resolves nothing,
// and its row still holds the globally unique host, so no other tenant can
// claim it and the tenant that removed it can take it back.
const (
	DomainStateActive   = 1
	DomainStateInactive = 2
)

// userStateActive is users.state for an account that can sign in. The value is
// declared in internal/user, and that package imports this one, so the owner
// count carries its own copy rather than closing the cycle.
const userStateActive = 1

// The tenant roles. A person who holds one of them administers the whole
// tenant, so the console admits them. The tenant owns tenant membership, so the
// names are declared here and no roles table exists.
const (
	RoleIAMOwner = "IAM_OWNER"
	RoleIAMAdmin = "IAM_ADMIN"
)

// Tenant is one row of tenants. DefaultOrgID is empty until bootstrap points the
// tenant at its default organization.
type Tenant struct {
	bun.BaseModel `bun:"table:tenants"`

	ID           string    `bun:"id,pk"`
	Name         string    `bun:"name"`
	State        int       `bun:"state"`
	DefaultOrgID string    `bun:"default_org_id,nullzero"`
	CreatedAt    time.Time `bun:"created_at"`
	DeletedAt    time.Time `bun:",soft_delete,nullzero"`
}

// Member is one row of tenant_members: the tenant roles of one person.
type Member struct {
	bun.BaseModel `bun:"table:tenant_members,alias:m"`

	TenantID  string    `bun:"tenant_id,pk"`
	UserID    string    `bun:"user_id,pk"`
	Roles     []string  `bun:"roles"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
	DeletedAt time.Time `bun:",soft_delete,nullzero"`

	// UserName is the person behind the membership, joined by the roster read.
	// It is empty everywhere else, because no column of this table holds it.
	UserName string `bun:"user_name,scanonly"`
}

// Domain is one row of tenant_domains. The domain is the bare host, lowercased,
// with a port only for a non-standard listener.
type Domain struct {
	bun.BaseModel `bun:"table:tenant_domains"`

	Domain     string    `bun:"domain,pk"`
	TenantID   string    `bun:"tenant_id"`
	IsPrimary  bool      `bun:"is_primary"`
	IsVerified bool      `bun:"is_verified"`
	State      int       `bun:"state"`
	DeletedAt  time.Time `bun:",soft_delete,nullzero"`
}

// Repository reads the tenant domains.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// TenantIDByDomain maps a hostname to the tenant that owns it. An unverified or
// an inactive domain never resolves, so a domain under verification cannot serve
// a token. A miss returns ErrDomainNotFound.
func (r *Repository) TenantIDByDomain(ctx context.Context, domain string) (string, error) {
	r.log.Debug("resolve tenant domain", logger.String("domain", domain))

	var row Domain
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Column("tenant_id").
		Where("domain = ?", domain).
		Where("state = ?", DomainStateActive).
		Where("is_verified = 1").
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrDomainNotFound, domain)
	}
	if err != nil {
		return "", fmt.Errorf("resolve tenant domain %s: %w", domain, err)
	}

	r.log.Debug("resolved tenant domain",
		logger.String("domain", domain), logger.String("tenant_id", row.TenantID))
	return row.TenantID, nil
}

// FindByID reads one live tenant. A soft-deleted tenant returns
// ErrTenantNotFound.
func (r *Repository) FindByID(ctx context.Context, tenantID string) (Tenant, error) {
	r.log.Debug("read tenant", logger.String("tenant_id", tenantID))

	var row Tenant
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("id = ?", tenantID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, tenantID)
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("read tenant %s: %w", tenantID, err)
	}
	return row, nil
}

// ListDomains reads the live domains of one tenant, the primary one first. An
// inactive domain, an unverified one, and a soft-deleted one never come back,
// so this read and TenantIDByDomain agree on which domains serve requests.
func (r *Repository) ListDomains(ctx context.Context, tenantID string) ([]Domain, error) {
	r.log.Debug("read tenant domains", logger.String("tenant_id", tenantID))

	var rows []Domain
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID).
		Where("state = ?", DomainStateActive).
		Where("is_verified = 1").
		Order("is_primary DESC", "domain ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read domains of tenant %s: %w", tenantID, err)
	}
	return rows, nil
}

// MemberRoles reads the tenant roles of one person. A person with no live row
// holds no role, which is the normal case, so the miss is not an error.
func (r *Repository) MemberRoles(ctx context.Context, tenantID, userID string) ([]string, error) {
	row, err := r.FindMember(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return row.Roles, nil
}

// IsManager reports whether one person administers the tenant.
//
// Every other domain reads MemberRoles and compares the two constants above.
// internal/audit cannot: this package records its own writes through it, so an
// import of these names would close a cycle. The audit feed takes this method as
// a function value instead.
func (r *Repository) IsManager(ctx context.Context, tenantID, userID string) (bool, error) {
	roles, err := r.MemberRoles(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	return slices.Contains(roles, RoleIAMOwner) || slices.Contains(roles, RoleIAMAdmin), nil
}

// CountOwners reads how many people sit as IAM_OWNER of one tenant.
//
// The membership write and the user write both read it to refuse the last owner
// out of service. roles is a JSON array in a TEXT column, so the match is
// JSON_CONTAINS and not LIKE: a LIKE would also match a role name that merely
// contains this one.
//
// The count joins the account, because a seat only counts while somebody can
// take it. A user delete leaves the membership row live, and a deactivate
// leaves the account unable to sign in, so a count over the rows alone reports
// an owner that nobody is. Two deletes would then each read two and each pass,
// and the tenant would end with no owner it can reach.
func (r *Repository) CountOwners(ctx context.Context, tenantID string) (int64, error) {
	r.log.Debug("count the owners of the tenant", logger.String("tenant_id", tenantID))

	total, err := db.Conn(ctx, r.db).NewSelect().
		Model((*Member)(nil)).
		Join("JOIN users AS u ON u.id = m.user_id AND u.tenant_id = m.tenant_id").
		Where("u.deleted_at IS NULL").
		Where("u.state = ?", userStateActive).
		Where("m.tenant_id = ?", tenantID).
		Where("JSON_CONTAINS(m.roles, ?)", `"`+RoleIAMOwner+`"`).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count the owners of tenant %s: %w", tenantID, err)
	}
	return int64(total), nil
}

// FindMember reads the live tenant membership of one person. A person with no
// live row holds no membership, which is the normal case, so the miss answers an
// empty row and not an error.
func (r *Repository) FindMember(ctx context.Context, tenantID, userID string) (Member, error) {
	r.log.Debug("read tenant member",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))

	var row Member
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, nil
	}
	if err != nil {
		return Member{}, fmt.Errorf("read tenant member of tenant %s: %w", tenantID, err)
	}
	return row, nil
}

// ListMembers reads one page of the administrator roster of a tenant, and the
// total behind it. Each row names the person, so the console renders a name
// instead of an id.
//
// A membership on a deleted account never comes back. The account is what the
// read joins from, so a membership nobody can sign in as is not a row an
// operator can act on.
func (r *Repository) ListMembers(
	ctx context.Context, tenantID string, desc bool, limit, offset int,
) ([]Member, int64, error) {
	r.log.Debug("list tenant members",
		logger.String("tenant_id", tenantID), logger.Int("offset", offset))

	order := "m.created_at ASC"
	if desc {
		order = "m.created_at DESC"
	}

	var rows []Member
	total, err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("m.tenant_id, m.user_id, m.roles, m.created_at").
		ColumnExpr(memberNameColumn).
		Join("JOIN users AS u ON u.id = m.user_id AND u.tenant_id = m.tenant_id AND u.deleted_at IS NULL").
		Join("LEFT JOIN user_humans AS h ON h.user_id = m.user_id AND h.tenant_id = m.tenant_id").
		Where("m.tenant_id = ?", tenantID).
		// The user id breaks a tie, so two memberships granted in the same
		// millisecond keep one order across the pages of one walk.
		OrderExpr(order).Order("m.user_id DESC").
		Limit(limit).Offset(offset).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list the members of tenant %s: %w", tenantID, err)
	}
	return rows, int64(total), nil
}

// memberNameColumn is what the console renders for one person: the display name
// of the profile, or the username when the profile carries none.
const memberNameColumn = `COALESCE(NULLIF(h.display_name, ''), u.username, '') AS user_name`

// SaveMember grants one tenant membership, or replaces the roles of one that
// already exists. It runs on the caller's transaction.
//
// The key of the table does not carry deleted_at, so a revoked membership
// occupies the key its person would take again. The write therefore clears the
// mark instead of failing: re-adding a revoked membership is what the console
// offers, and it restores the access the roles grant.
//
// created_at is not written again, so the column keeps naming when the person
// first entered the roster.
func (r *Repository) SaveMember(ctx context.Context, row Member) error {
	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		On("DUPLICATE KEY UPDATE").
		Set("roles = VALUES(roles)").
		Set("deleted_at = NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write the tenant membership of user %s of tenant %s: %w",
			row.UserID, row.TenantID, err)
	}
	return nil
}

// DeleteMember revokes one tenant membership. The row stays in the database,
// and every read filters it out. It runs on the caller's transaction.
//
// A membership nobody holds returns ErrMemberNotFound, so a revoke of a row
// that already went answers 404 and not a silent success.
func (r *Repository) DeleteMember(ctx context.Context, tenantID, userID string) error {
	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Member)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("revoke the tenant membership of user %s of tenant %s: %w",
			userID, tenantID, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke the tenant membership of user %s of tenant %s: %w",
			userID, tenantID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrMemberNotFound, userID)
	}
	return nil
}
