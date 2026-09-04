// Package tenant holds the tenant domain: the tenants themselves and the
// hostnames that belong to them.
package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

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

// ErrLastLocalOwner reports a write that would leave the tenant with no
// IAM_OWNER whom the local password compare still signs in.
//
// It is not ErrLastOwner. A tenant can hold ten owners a directory proves and
// one owner this gateway proves, and the count of owners is then never the
// question: one directory outage takes the ten with it, and the eleventh is the
// only administrator left. See docs/specs/0002-directory-sign-in.md.
var ErrLastLocalOwner = errors.New("the tenant would keep no local owner")

// userStateActive is users.state for an account that can sign in. The value is
// declared in internal/user, and that package imports this one, so the owner
// count carries its own copy rather than closing the cycle.
const userStateActive = 1

// federationStateActive is user_federations.state for a federation that proves a
// sign-in. The value is declared in internal/userfederation, and that package
// imports this one, so the local owner read carries its own copy rather than
// closing the cycle.
const federationStateActive = 1

// The tenant roles. A person who holds one of them administers the whole
// tenant, so the console admits them. The tenant owns tenant membership, so the
// names are declared here and no roles table exists.
const (
	RoleIAMOwner = "IAM_OWNER"
	RoleIAMAdmin = "IAM_ADMIN"
)

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
	r.log.Debug("resolve tenant domain", logger.String("domain", domain), logger.RequestID(ctx))

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
		logger.String("domain", domain), logger.String("tenant_id", row.TenantID), logger.RequestID(ctx))
	return row.TenantID, nil
}

// FindByID reads one live tenant. A soft-deleted tenant returns
// ErrTenantNotFound.
func (r *Repository) FindByID(ctx context.Context, tenantID string) (Tenant, error) {
	r.log.Debug("read tenant", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

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
	r.log.Debug("read tenant domains", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

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
	r.log.Debug("count the owners of the tenant", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

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

// LocalOwners reads every IAM_OWNER of one tenant whom the local password
// compare still signs in.
//
// It is the read behind the first guard rail of docs/specs/0002-directory-sign-in.md:
// never leave a tenant with zero local IAM_OWNER. CountOwners cannot answer it,
// because a tenant whose owners a directory proves counts owners it cannot reach
// while that directory is off.
//
// A local owner is an owner that Federation Resolution case 3 answers for. Four
// predicates say so, and each one matches a case of the resolver:
//
//   - The account is live and active, and the membership carries IAM_OWNER. This
//     is what CountOwners already reads.
//   - The person holds a password hash. A NULL or empty hash proves nothing, so
//     that person signs in through a directory or not at all.
//   - The person holds no Federation Link with a live active federation. Case 2 sends
//     them to that federation and never to the local compare.
//   - No live active federation claims the domain of their email address. Case 1
//     outranks case 3, so a claim routes them even though they hold a hash.
//
// The email comes back with the row, lowercased, because the guard that refuses
// a domain claim matches the claimed domains against it before the claim is
// written.
func (r *Repository) LocalOwners(ctx context.Context, tenantID string) ([]LocalOwner, error) {
	r.log.Debug("read the local owners of the tenant",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var rows []LocalOwner
	err := db.Conn(ctx, r.db).NewSelect().
		Model((*Member)(nil)).
		ColumnExpr("m.user_id AS user_id").
		ColumnExpr("LOWER(IFNULL(h.email, '')) AS email").
		Join("JOIN users AS u ON u.id = m.user_id AND u.tenant_id = m.tenant_id").
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.deleted_at IS NULL").
		Where("u.state = ?", userStateActive).
		Where("m.tenant_id = ?", tenantID).
		Where("JSON_CONTAINS(m.roles, ?)", `"`+RoleIAMOwner+`"`).
		Where("h.password_hash IS NOT NULL").
		Where("h.password_hash <> ''").
		Where(`NOT EXISTS (
			SELECT 1 FROM user_federation_links AS l
			JOIN user_federations AS lp
			  ON lp.id = l.federation_id AND lp.tenant_id = l.tenant_id AND lp.deleted_at IS NULL
			WHERE l.tenant_id = m.tenant_id AND l.user_id = m.user_id AND lp.state = ?
		)`, federationStateActive).
		Where(`NOT EXISTS (
			SELECT 1 FROM user_federation_domains AS d
			JOIN user_federations AS dp
			  ON dp.id = d.federation_id AND dp.tenant_id = d.tenant_id AND dp.deleted_at IS NULL
			WHERE d.tenant_id = m.tenant_id AND d.deleted_at IS NULL AND dp.state = ?
			  AND d.domain = SUBSTRING_INDEX(LOWER(h.email), '@', -1)
		)`, federationStateActive).
		Order("m.user_id ASC").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read the local owners of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("found the local owners of the tenant",
		logger.String("tenant_id", tenantID), logger.Int("count", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// FindMember reads the live tenant membership of one person. A person with no
// live row holds no membership, which is the normal case, so the miss answers an
// empty row and not an error.
func (r *Repository) FindMember(ctx context.Context, tenantID, userID string) (Member, error) {
	r.log.Debug("read tenant member",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

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
		logger.String("tenant_id", tenantID), logger.Int("offset", offset), logger.RequestID(ctx))

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
	r.log.Debug("save tenant member",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))

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
	r.log.Debug("saved tenant member",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))
	return nil
}

// DeleteMember revokes one tenant membership. The row stays in the database,
// and every read filters it out. It runs on the caller's transaction.
//
// A membership nobody holds returns ErrMemberNotFound, so a revoke of a row
// that already went answers 404 and not a silent success.
func (r *Repository) DeleteMember(ctx context.Context, tenantID, userID string) error {
	r.log.Debug("delete tenant member",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

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
	r.log.Debug("deleted tenant member",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))
	return nil
}

// PeopleAtDomains reads the people of one tenant whose email address carries one
// of the given domains, and the total behind the page.
//
// It is the read behind the claim preview of docs/specs/0002-directory-sign-in.md:
// the console names the people a domain claim moves before it saves. Federation
// Resolution case 1 outranks every case below it, so a claim routes every one of
// these people to the directory, including the people who hold a local password
// and no directory account. Those are the ones the preview is for, because every
// one of them stops signing in with the password they hold.
//
// LocalOwners answers the subset the refusal is about. This read answers the
// whole population, because a preview that named the subset would read as the
// whole blast radius and the people it dropped still move.
//
// Two forms carry the domain, and the read matches both, because Federation
// Resolution case 1 reads both: the identifier the person types, and the email
// address the tenant holds for them. A person whose username is an address at a
// claimed domain is routed by the claim even when their stored email is not, so
// a read of the email alone would under-report the population.
//
// The read filters the soft delete and nothing else. Every state comes back: a
// deactivated person is reactivated later, and the claim moves them when they
// are. The join is an inner join, so a machine account, which holds no
// user_humans row and no email address, is never in the answer.
//
// limit caps the rows. The total counts every match, so a tenant that holds a
// whole company at one domain reads the number without reading the company.
//
// ponytail: the domain is computed per row, so no index answers this and the
// scan is the whole tenant. LocalOwners already reads the same shape. Add a
// functional key part on the email domain when a tenant grows large enough to
// feel it.
func (r *Repository) PeopleAtDomains(
	ctx context.Context, tenantID string, domains []string, limit int,
) ([]DomainPerson, int, error) {
	r.log.Debug("read the people at the claimed domains",
		logger.String("tenant_id", tenantID), logger.Int("domains", len(domains)),
		logger.RequestID(ctx))

	// An empty list moves nobody, and IN () is not a query. Every caller reads
	// the same empty answer the match below would give.
	if len(domains) == 0 {
		r.log.Debug("found no people, because the claim names no domain",
			logger.String("tenant_id", tenantID), logger.RequestID(ctx))
		return nil, 0, nil
	}

	lowered := make([]string, 0, len(domains))
	for _, domain := range domains {
		lowered = append(lowered, strings.ToLower(domain))
	}

	var rows []DomainPerson
	total, err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ModelTableExpr("users AS u").
		ColumnExpr("u.id AS user_id").
		ColumnExpr("u.username AS username").
		ColumnExpr("LOWER(h.email) AS email").
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.tenant_id = ?", tenantID).
		Where("u.deleted_at IS NULL").
		Where("SUBSTRING_INDEX(LOWER(h.email), '@', -1) IN (?) "+
			"OR SUBSTRING_INDEX(LOWER(u.username), '@', -1) IN (?)",
			bun.In(lowered), bun.In(lowered)).
		Order("u.id ASC").
		Limit(limit).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read the people at the claimed domains of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("found the people at the claimed domains",
		logger.String("tenant_id", tenantID), logger.Int("total", total),
		logger.RequestID(ctx))
	return rows, total, nil
}
