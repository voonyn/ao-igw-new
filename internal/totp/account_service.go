package totp

import (
	"context"
	"errors"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// Status is the Second Factor of one account as the person who owns it reads it.
//
// It carries no shared secret and no code. A page that states whether a factor
// is on needs neither, and both are credentials.
//
// A pending enrolment reads as no factor. The secret is minted and nobody has
// proved a code with it, so a page that called it a factor would tell a person
// they are protected when they are not.
type Status struct {
	Active            bool
	ActivatedAt       time.Time
	RecoveryRemaining int
}

// AccountStatus answers the Second Factor state of the person the access token
// names.
//
// The count is read only for an active factor. A person who holds none has no
// Recovery Codes either, and the zero the caller receives is the whole answer.
func (s *Service) AccountStatus(ctx context.Context, tenantID string, who Principal) (Status, error) {
	s.log.Debug("read the second factor state",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	row, err := s.deps.Find(ctx, tenantID, who.UserID)
	if errors.Is(err, ErrNoEnrolment) || (err == nil && !row.Active()) {
		return Status{}, nil
	}
	if err != nil {
		s.log.Error("read the totp enrolment",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Status{}, err
	}

	remaining, err := s.deps.CountRecoveryCodes(ctx, tenantID, who.UserID)
	if err != nil {
		s.log.Error("count the recovery codes",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Status{}, err
	}

	s.log.Debug("read the active second factor",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.Int("recovery_codes", remaining), logger.RequestID(ctx))
	return Status{Active: true, ActivatedAt: row.ActivatedAt, RecoveryRemaining: remaining}, nil
}

// AccountStart mints a pending TOTP Enrolment for the person the access token
// names.
//
// It demands no proof beyond that token. A start against an active factor is
// refused, which is the one guard the portal path needs: a second secret minted
// over a live factor would replace what the person already scanned. An
// activation needs no guard of its own, because the code is the proof.
//
// The body is the one the sign-in path runs, so the provisioning URI is
// identical: the same tenant label and the same person label.
func (s *Service) AccountStart(
	ctx context.Context, tenantID, issuer string, who Principal,
) (Started, error) {
	s.log.Debug("start a totp enrolment from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	return s.start(ctx, tenantID, issuer, who)
}

// AccountActivate proves the pending secret with a code and records the Second
// Factor of the person the access token names.
//
// It answers the Recovery Codes and nothing else. No login session waits on this
// enrolment, so no token rotates here.
//
// The code and the Recovery Codes never reach a log line.
func (s *Service) AccountActivate(
	ctx context.Context, tenantID string, who Principal, code string,
) ([]string, error) {
	s.log.Debug("activate a totp enrolment from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	return s.activate(ctx, tenantID, who, code, nil)
}

// AccountRemove destroys the Second Factor of the person the access token names,
// once they prove the password stored now.
//
// The password is checked before anything is read or written. The access token
// carries no session identifier and the bearer guard reads no store, so this
// body field is the only proof the request can hold. Without it, a leaked access
// token strips the account of its Second Factor in one request.
//
// The delete is hard, and it takes the shared secret and every Recovery Code
// with it. A later enrolment then starts clean, which is the point: a person who
// changed phones adds a new Authenticator here.
//
// No other Login Session ends. Each of them proved the Factor when it was
// created, and the portal already offers a sign-out-everywhere control for the
// compromise case.
//
// The password never reaches a log line.
func (s *Service) AccountRemove(
	ctx context.Context, tenantID string, who Principal, password string,
) error {
	s.log.Debug("remove a second factor from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	if err := s.deps.VerifyPassword(ctx, tenantID, who.UserID, password); err != nil {
		return err
	}
	if _, err := s.activeFactor(ctx, tenantID, who); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.ClearFactor(ctx, tenantID, who.UserID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    who.UserID,
			Action:     audit.ActionMFARemoved,
			EntityType: audit.EntityUser,
			EntityID:   who.UserID,
			IP:         who.IP,
			UserAgent:  who.UserAgent,
		})
	})
	if err != nil {
		s.log.Error("remove the second factor",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return err
	}

	s.log.Info("removed a second factor",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID))
	return nil
}

// AccountReplaceRecoveryCodes issues a new set of Recovery Codes to the person
// the access token names, once they prove the password stored now.
//
// Every old code is voided by the same write. A person who spent codes, or who
// believes the printed set leaked, replaces the whole set here.
//
// The codes are disclosed exactly once, in the answer. The database holds
// digests, so no later read can name them again. Neither the password nor a code
// reaches a log line.
func (s *Service) AccountReplaceRecoveryCodes(
	ctx context.Context, tenantID string, who Principal, password string,
) ([]string, error) {
	s.log.Debug("replace the recovery codes from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	if err := s.deps.VerifyPassword(ctx, tenantID, who.UserID, password); err != nil {
		return nil, err
	}
	if _, err := s.activeFactor(ctx, tenantID, who); err != nil {
		return nil, err
	}

	shown, digests, err := newRecoveryCodes()
	if err != nil {
		s.log.Error("mint the recovery codes",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.SaveRecoveryCodes(ctx, tenantID, who.UserID, digests); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    who.UserID,
			Action:     audit.ActionMFARecoveryCodesRegenerated,
			EntityType: audit.EntityUser,
			EntityID:   who.UserID,
			IP:         who.IP,
			UserAgent:  who.UserAgent,
		})
	})
	if err != nil {
		s.log.Error("replace the recovery codes",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, err
	}

	s.log.Info("replaced the recovery codes",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID))
	return shown, nil
}
