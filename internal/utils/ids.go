package utils

import "github.com/google/uuid"

// Typed IDs prevent argument-swap bugs (passing a UserID where an OrgID is
// expected fails at compile time). All IDs are UUIDv7: time-ordered, so they
// index well as primary keys and sort by creation time. They live in utils
// because they are referenced across domains (a Session carries a UserID and
// an OrgID; an AuditEntry carries both).

type (
	TenantID  struct{ uuid.UUID }
	OrgID     struct{ uuid.UUID }
	UserID    struct{ uuid.UUID }
	ProjectID struct{ uuid.UUID }
	AppID     struct{ uuid.UUID }
	ScopeID   struct{ uuid.UUID }
	SessionID struct{ uuid.UUID }
	AuditID   struct{ uuid.UUID }
)

func NewTenantID() TenantID   { return TenantID{mustV7()} }
func NewOrgID() OrgID         { return OrgID{mustV7()} }
func NewUserID() UserID       { return UserID{mustV7()} }
func NewProjectID() ProjectID { return ProjectID{mustV7()} }
func NewAppID() AppID         { return AppID{mustV7()} }
func NewScopeID() ScopeID     { return ScopeID{mustV7()} }
func NewSessionID() SessionID { return SessionID{mustV7()} }
func NewAuditID() AuditID     { return AuditID{mustV7()} }

func ParseTenantID(s string) (TenantID, error) {
	id, err := uuid.Parse(s)
	return TenantID{id}, err
}

func ParseOrgID(s string) (OrgID, error) {
	id, err := uuid.Parse(s)
	return OrgID{id}, err
}

func ParseUserID(s string) (UserID, error) {
	id, err := uuid.Parse(s)
	return UserID{id}, err
}

func ParseProjectID(s string) (ProjectID, error) {
	id, err := uuid.Parse(s)
	return ProjectID{id}, err
}

func ParseAppID(s string) (AppID, error) {
	id, err := uuid.Parse(s)
	return AppID{id}, err
}

func ParseSessionID(s string) (SessionID, error) {
	id, err := uuid.Parse(s)
	return SessionID{id}, err
}

// mustV7 panics only if the system clock/entropy is broken — unrecoverable.
func mustV7() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("uuid v7 generation failed: " + err.Error())
	}
	return id
}

// NewUUIDv7 returns a new time-ordered UUIDv7 string.
// Panics if the OS entropy source fails (same contract as uuid.MustNewRandom).
func NewUUIDv7() string {
	return mustV7().String()
}
