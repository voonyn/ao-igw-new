// Package user holds the people of a tenant. A user row is the account, and a
// user_humans row is the person behind it.
package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNotFound reports that the caller's own identity names no live user of the
// tenant. It answers 401, the same answer a wrong password gets, so the response
// never says which people a tenant holds. The handler file registers it.
var ErrNotFound = errors.New("user not found")

// ErrNoSuchUser reports that no live user of the tenant carries the id an
// administrator named. It answers 404.
//
// It is a second sentinel on purpose. ErrNotFound describes the caller, and this
// one describes a row the caller asked for, so the two answer different statuses.
var ErrNoSuchUser = errors.New("no such user")

// ErrDuplicateUsername reports a username another live account of the tenant
// already holds. The unique key on users refuses it, and this turns that refusal
// into an answer the console can read.
var ErrDuplicateUsername = errors.New("duplicate username")

// The values users.state holds. StateActive is an account that can sign in, and
// StateLocked is one the lockout policy stopped.
const (
	StateActive   = 1
	StateInactive = 2
	StateDeleted  = 3
	StateLocked   = 4
	StateInitial  = 5
)

// The values users.user_type holds. Only a person signs in.
const (
	TypeHuman   = 1
	TypeMachine = 2
)

// stateActive is users.state for an account that can sign in.
const stateActive = StateActive

// typeHuman is users.user_type for a person. Only a person signs in.
const typeHuman = TypeHuman

// The values account_tokens.purpose holds. An invitation is the third: the
// person it names has an account but has never signed in, and the link is how
// they set the password that activates it.
const (
	PurposePasswordReset = 1
	PurposeEmailVerify   = 2
	PurposeInvitation    = 3
)

// mysqlDuplicateEntry is the MySQL error number of a unique key violation.
const mysqlDuplicateEntry = 1062

// User is one row of users joined to its user_humans row: the account and the
// person behind it.
//
// PasswordHash holds a bcrypt hash, never the password. It never reaches a log
// line and never leaves this package in a response.
type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	OrgID    string `bun:"org_id"`
	Username string `bun:"username,nullzero"`
	UserType int    `bun:"user_type"`
	State    int    `bun:"state"`

	CreatedAt  time.Time `bun:"created_at,nullzero"`
	LastAuthAt time.Time `bun:"last_auth_at,nullzero"`

	// The columns of the joined user_humans row, and the second factor derived
	// beside it. A machine account holds no such row, so every one of them is
	// empty for one.
	DisplayName     string `bun:"display_name,scanonly"`
	Email           string `bun:"email,scanonly"`
	IsEmailVerified bool   `bun:"is_email_verified,scanonly"`
	PasswordHash    string `bun:"password_hash,scanonly"`

	FirstName         string    `bun:"first_name,scanonly"`
	LastName          string    `bun:"last_name,scanonly"`
	Lang              string    `bun:"preferred_language,scanonly"`
	Phone             string    `bun:"phone,scanonly"`
	IsPhoneVerified   bool      `bun:"is_phone_verified,scanonly"`
	PasswordChangeReq bool      `bun:"password_change_required,scanonly"`
	PasswordChangedAt time.Time `bun:"password_changed_at,scanonly,nullzero"`
	MFAEnabled        bool      `bun:"mfa_enabled,scanonly"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// Human is one row of user_humans: the person behind one account. A machine
// account holds no such row.
//
// PasswordHash holds a bcrypt hash, never the password. It never reaches a log
// line and never leaves this package in a response.
type Human struct {
	bun.BaseModel `bun:"table:user_humans,alias:h"`

	UserID   string `bun:"user_id,pk"`
	TenantID string `bun:"tenant_id,pk"`

	FirstName   string `bun:"first_name,nullzero"`
	LastName    string `bun:"last_name,nullzero"`
	DisplayName string `bun:"display_name,nullzero"`
	Lang        string `bun:"preferred_language,nullzero"`

	Email           string `bun:"email,nullzero"`
	IsEmailVerified bool   `bun:"is_email_verified"`
	Phone           string `bun:"phone,nullzero"`

	PasswordHash string `bun:"password_hash,nullzero"`

	CreatedAt time.Time `bun:"created_at,nullzero"`
}

// AccountToken is one row of account_tokens: a single-use, time-limited value a
// person redeems once.
//
// TokenHash holds a SHA-256 digest, never the token itself. The token is
// disclosed exactly once, in the answer of the request that minted it.
type AccountToken struct {
	bun.BaseModel `bun:"table:account_tokens"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	UserID   string `bun:"user_id"`
	Purpose  int    `bun:"purpose"`

	TokenHash string    `bun:"token_hash"`
	ExpiresAt time.Time `bun:"expires_at"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
}

// userColumns names every column the User model holds. The table carries more
// columns than the model does, and a select of them all fails to scan, so the
// list is written out here.
const userColumns = `u.id, u.tenant_id, u.org_id, u.username, u.user_type, u.state, u.deleted_at`

// adminUserColumns names what an administrative read of one account projects.
// It carries created_at and last_auth_at, which the login reads do not need.
const adminUserColumns = `u.id, u.tenant_id, u.org_id, u.username, u.user_type, u.state,
	u.created_at, u.last_auth_at, u.deleted_at`

// humanJoin reads the person behind each account. It is a LEFT JOIN, because a
// machine account holds no user_humans row and must still appear in the list.
//
// The stored password hash is not projected. An administrative read never needs
// it, and a column that is never selected cannot leak into an answer.
const humanJoin = "LEFT JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id"

// humanColumns names the person behind one account, as an administrative read
// projects it. Every one of them is empty for a machine account.
const humanColumns = `h.first_name AS first_name, h.last_name AS last_name,
	h.display_name AS display_name, h.preferred_language AS preferred_language,
	h.email AS email, h.is_email_verified AS is_email_verified,
	h.phone AS phone, h.is_phone_verified AS is_phone_verified,
	h.password_change_required AS password_change_required,
	h.password_changed_at AS password_changed_at`

// mfaColumn reports whether the account holds a second factor: an activated TOTP
// secret, or one registered passkey. The console renders one flag for both, so
// the read answers one flag.
const mfaColumn = `(EXISTS (SELECT 1 FROM user_totp AS t
		WHERE t.tenant_id = u.tenant_id AND t.user_id = u.id
		  AND t.activated_at IS NOT NULL AND t.deleted_at IS NULL)
	OR EXISTS (SELECT 1 FROM user_webauthn_credentials AS w
		WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id
		  AND w.deleted_at IS NULL)) AS mfa_enabled`

// sortColumns maps a sort key of the route's allowlist to its column. The ORDER
// BY clause is built from this map only, so no query input reaches the SQL.
var sortColumns = map[string]string{
	"username": "u.username",
	"state":    "u.state",
	"created":  "u.created_at",
}

// Repository reads the users of one tenant.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// FindByIdentifier reads the person one identifier names. The identifier is a
// username or an email address, because a tenant lets a person type either.
//
// An inactive account and a soft-deleted one never come back. A miss returns
// ErrNotFound. The identifier is personal data, so it never reaches a log line.
func (r *Repository) FindByIdentifier(ctx context.Context, tenantID, identifier string) (User, error) {
	r.log.Debug("read user by identifier", logger.String("tenant_id", tenantID))

	var row User
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		ColumnExpr(userColumns).
		ColumnExpr("h.email AS email").
		ColumnExpr("h.is_email_verified AS is_email_verified").
		ColumnExpr("h.password_hash AS password_hash").
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.tenant_id = ?", tenantID).
		Where("u.state = ?", stateActive).
		Where("u.user_type = ?", typeHuman).
		Where("u.username = ? OR h.email = ?", identifier, identifier).
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
	}
	if err != nil {
		return User{}, fmt.Errorf("read user of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("read user by identifier",
		logger.String("tenant_id", tenantID), logger.String("user_id", row.ID))
	return row, nil
}

// FindPasswordHash reads the stored bcrypt hash of one person. An inactive
// account and a soft-deleted one never come back, so a disabled person cannot
// sign in with a session the identifier step opened before.
//
// The hash is a credential. It never reaches a log line and never leaves this
// package in a response. A miss returns ErrNotFound.
func (r *Repository) FindPasswordHash(ctx context.Context, tenantID, userID string) (string, error) {
	r.log.Debug("read password hash",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))

	var row User
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		ColumnExpr("u.id").
		ColumnExpr("h.password_hash AS password_hash").
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.tenant_id = ?", tenantID).
		Where("u.id = ?", userID).
		Where("u.state = ?", stateActive).
		Where("u.user_type = ?", typeHuman).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: tenant %s, user %s", ErrNotFound, tenantID, userID)
	}
	if err != nil {
		return "", fmt.Errorf("read password hash of tenant %s: %w", tenantID, err)
	}

	return row.PasswordHash, nil
}

// FindByID reads one person by the id an access token carries, with the human
// profile the admin front door answers with.
//
// An inactive account and a soft-deleted one never come back, so a person the
// tenant disabled cannot reach the admin API with a token that still has time
// left. A miss returns ErrNotFound.
func (r *Repository) FindByID(ctx context.Context, tenantID, userID string) (User, error) {
	r.log.Debug("read user by id",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))

	var row User
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		ColumnExpr(userColumns).
		ColumnExpr("h.display_name AS display_name").
		ColumnExpr("h.email AS email").
		ColumnExpr("h.is_email_verified AS is_email_verified").
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.tenant_id = ?", tenantID).
		Where("u.id = ?", userID).
		Where("u.state = ?", stateActive).
		Where("u.user_type = ?", typeHuman).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: tenant %s, user %s", ErrNotFound, tenantID, userID)
	}
	if err != nil {
		return User{}, fmt.Errorf("read user %s of tenant %s: %w", userID, tenantID, err)
	}

	return row, nil
}

// List reads one page of the people of a tenant, and the total behind it.
//
// Every state comes back, because the console filters by state itself. A
// soft-deleted account never does. A machine account comes back with an empty
// person, because it holds no user_humans row.
func (r *Repository) List(ctx context.Context, tenantID string, q Query) ([]User, int64, error) {
	r.log.Debug("list users",
		logger.String("tenant_id", tenantID), logger.Int("offset", q.Offset))

	var rows []User
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr(adminUserColumns).
		ColumnExpr(humanColumns).
		ColumnExpr(mfaColumn).
		Join(humanJoin).
		Where("u.tenant_id = ?", tenantID)

	// The search term is personal data, so it narrows the query and never
	// reaches a log line.
	if q.Search != "" {
		sel = sel.Where("u.username LIKE ? OR h.email LIKE ?", q.Search+"%", q.Search+"%")
	}
	if q.State != 0 {
		sel = sel.Where("u.state = ?", q.State)
	}
	if q.UserType != 0 {
		sel = sel.Where("u.user_type = ?", q.UserType)
	}
	if q.OrgID != "" {
		sel = sel.Where("u.org_id = ?", q.OrgID)
	}

	// The id breaks a tie, so two accounts created in the same millisecond keep
	// one order across the pages of one walk.
	sel = sel.OrderExpr(orderBy(q)).Order("u.id DESC").
		Limit(q.Limit).Offset(q.Offset)

	total, err := sel.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list users of tenant %s: %w", tenantID, err)
	}
	return rows, int64(total), nil
}

// orderBy names the column and the direction one page reads in. An unknown key
// never reaches here, because the route refuses it, so a key this map does not
// hold takes the newest-first default.
func orderBy(q Query) string {
	column, ok := sortColumns[q.Sort]
	if !ok {
		return "u.created_at DESC"
	}
	if q.Desc {
		return column + " DESC"
	}
	return column + " ASC"
}

// Read reads one live account of a tenant in any state, with the person behind
// it. A miss returns ErrNoSuchUser.
//
// It is the administrative read. FindByID above answers the caller's own
// identity and admits an active account only, because a person the tenant
// disabled must not reach the admin API with a token that still has time left.
// An administrator, on the other hand, must be able to read the account they are
// about to reactivate.
func (r *Repository) Read(ctx context.Context, tenantID, userID string) (User, error) {
	r.log.Debug("read user for administration",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))

	var row User
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		ColumnExpr(adminUserColumns).
		ColumnExpr(humanColumns).
		ColumnExpr(mfaColumn).
		Join(humanJoin).
		Where("u.tenant_id = ?", tenantID).
		Where("u.id = ?", userID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: %s", ErrNoSuchUser, userID)
	}
	if err != nil {
		return User{}, fmt.Errorf("read user %s of tenant %s: %w", userID, tenantID, err)
	}
	return row, nil
}

// Insert writes one new account. It runs on the caller's transaction.
//
// A username another live account of the tenant holds returns
// ErrDuplicateUsername, because the unique key refuses it.
func (r *Repository) Insert(ctx context.Context, row User) error {
	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		if isDuplicate(err) {
			return fmt.Errorf("%w: %s", ErrDuplicateUsername, row.Username)
		}
		return fmt.Errorf("write user %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	return nil
}

// InsertHuman writes the person behind one new account. It runs on the caller's
// transaction, so the account and the person land together.
func (r *Repository) InsertHuman(ctx context.Context, row Human) error {
	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write person of user %s of tenant %s: %w", row.UserID, row.TenantID, err)
	}
	return nil
}

// UpdateHuman writes the profile of one person. It runs on the caller's
// transaction.
//
// The username, the email address, and the stored password hash are not written
// here. Each of them credentials a sign-in, and the update body carries none of
// them.
func (r *Repository) UpdateHuman(ctx context.Context, row Human) error {
	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("first_name", "last_name", "display_name", "preferred_language", "phone").
		Where("tenant_id = ?", row.TenantID).
		Where("user_id = ?", row.UserID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("update person of user %s of tenant %s: %w", row.UserID, row.TenantID, err)
	}
	return oneRow(res, row.TenantID, row.UserID, "update the person of")
}

// SetState writes the state of one live account. It runs on the caller's
// transaction.
func (r *Repository) SetState(ctx context.Context, tenantID, userID string, state int) error {
	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*User)(nil)).
		Set("state = ?", state).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", userID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("set the state of user %s of tenant %s: %w", userID, tenantID, err)
	}
	return oneRow(res, tenantID, userID, "set the state of")
}

// Unlock clears the lockout of one account and returns it to the active state.
// It runs on the caller's transaction.
//
// Both halves are needed. The three lockout columns hold the running count and
// the auto-expiring lock, and users.state holds the badge the console renders.
// Clearing one and not the other leaves the person locked out by whichever half
// stayed.
func (r *Repository) Unlock(ctx context.Context, tenantID, userID string) error {
	conn := db.Conn(ctx, r.db)

	res, err := conn.NewUpdate().
		Model((*User)(nil)).
		Set("state = ?", StateActive).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", userID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("unlock user %s of tenant %s: %w", userID, tenantID, err)
	}
	if err := oneRow(res, tenantID, userID, "unlock"); err != nil {
		return err
	}

	// A machine account holds no user_humans row, so no row here is a normal
	// answer.
	if _, err := conn.NewUpdate().
		Model((*Human)(nil)).
		Set("failed_login_count = 0").
		Set("last_failed_login_at = NULL").
		Set("locked_until = NULL").
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Exec(ctx); err != nil {
		return fmt.Errorf("clear the lockout of user %s of tenant %s: %w", userID, tenantID, err)
	}
	return nil
}

// SoftDelete marks one account deleted. The row stays in the database, and every
// read filters it out. It runs on the caller's transaction.
//
// The person behind the account stays as it is. user_humans has no deleted_at
// column, and the account row is what every read joins from, so a profile
// without a live account is unreachable.
func (r *Repository) SoftDelete(ctx context.Context, tenantID, userID string) error {
	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*User)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", userID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete user %s of tenant %s: %w", userID, tenantID, err)
	}
	return oneRow(res, tenantID, userID, "delete")
}

// InsertToken writes one account token. It runs on the caller's transaction. The
// row holds a digest, and the token itself is never written and never logged.
func (r *Repository) InsertToken(ctx context.Context, row AccountToken) error {
	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write account token of user %s of tenant %s: %w", row.UserID, row.TenantID, err)
	}
	return nil
}

// ClearMFA removes every second factor of one person: the TOTP secret, the
// recovery codes that go with it, and every registered passkey. It runs on the
// caller's transaction.
//
// A person with no second factor left is the normal outcome, so no row is not an
// error. The recovery codes are hard deleted, because a code is consumed once
// and the client cannot recover it. The TOTP row and the passkeys carry
// deleted_at, so bun marks them.
func (r *Repository) ClearMFA(ctx context.Context, tenantID, userID string) error {
	conn := db.Conn(ctx, r.db)

	if _, err := conn.NewDelete().
		Model((*totp)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Exec(ctx); err != nil {
		return fmt.Errorf("clear the TOTP factor of user %s of tenant %s: %w", userID, tenantID, err)
	}

	if _, err := conn.NewDelete().
		Model((*totpRecoveryCode)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		ForceDelete().
		Exec(ctx); err != nil {
		return fmt.Errorf("clear the recovery codes of user %s of tenant %s: %w", userID, tenantID, err)
	}

	if _, err := conn.NewDelete().
		Model((*passkey)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Exec(ctx); err != nil {
		return fmt.Errorf("clear the passkeys of user %s of tenant %s: %w", userID, tenantID, err)
	}
	return nil
}

// The three tables a second-factor reset clears. Only the keys are modelled,
// because the reset writes no other column of them.
type (
	totp struct {
		bun.BaseModel `bun:"table:user_totp"`

		TenantID  string    `bun:"tenant_id,pk"`
		UserID    string    `bun:"user_id,pk"`
		DeletedAt time.Time `bun:",soft_delete,nullzero"`
	}

	totpRecoveryCode struct {
		bun.BaseModel `bun:"table:user_totp_recovery_codes"`

		TenantID string `bun:"tenant_id,pk"`
		UserID   string `bun:"user_id,pk"`
		CodeHash string `bun:"code_hash,pk"`
	}

	passkey struct {
		bun.BaseModel `bun:"table:user_webauthn_credentials"`

		TenantID     string    `bun:"tenant_id,pk"`
		CredentialID []byte    `bun:"credential_id,pk"`
		UserID       string    `bun:"user_id"`
		DeletedAt    time.Time `bun:",soft_delete,nullzero"`
	}
)

// oneRow reports ErrNoSuchUser when a write matched no live row. The service
// read the row first, so this is a race, not a routine answer.
func oneRow(res sql.Result, tenantID, userID, what string) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s user %s of tenant %s: %w", what, userID, tenantID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrNoSuchUser, userID)
	}
	return nil
}

// isDuplicate reports the unique key violation of a username another live
// account already holds.
func isDuplicate(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == mysqlDuplicateEntry
}
