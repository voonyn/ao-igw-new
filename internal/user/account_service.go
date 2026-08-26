package user

import (
	"context"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ProfileUpdater writes the four identity fields of one person.
// Repository.UpdateProfile has this shape.
type ProfileUpdater func(ctx context.Context, row Human) error

// AccountDeps is what the self-service half of this domain reads and writes.
type AccountDeps struct {
	UpdateProfile ProfileUpdater

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AccountService answers the self-service account API.
//
// There is no role gate and no ownership check to write, because there is
// nothing to check: every method acts on the subject of the caller's token, and
// no method takes an account id. The bearer guard verified the subject.
type AccountService struct {
	deps AccountDeps
	log  logger.Logger
}

func NewAccountService(deps AccountDeps) *AccountService {
	return &AccountService{deps: deps, log: deps.Log}
}

// UpdateProfile writes the profile of the person who made the request.
//
// The account is a.UserID and nothing else names it. A body that carried
// another account id would not be read, because ProfileBody holds no such
// field.
func (s *AccountService) UpdateProfile(ctx context.Context, a Actor, body ProfileBody) error {
	s.log.Debug("update own profile",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	person := Human{
		UserID:      a.UserID,
		TenantID:    a.TenantID,
		FirstName:   body.FirstName,
		LastName:    body.LastName,
		DisplayName: body.DisplayName,
		Lang:        body.Locale,
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.UpdateProfile(ctx, person); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserUpdated, a.UserID))
	})
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "update own profile", err)
	}

	s.log.Info("updated own profile",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID))
	return nil
}

// fail logs the error where it stops bubbling up and returns it unchanged, so
// the mapper still reads the sentinel behind it.
func (s *AccountService) fail(tenantID, userID, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID),
		logger.Err(err))
	return err
}
