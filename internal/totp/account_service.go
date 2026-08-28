package totp

import (
	"context"
	"errors"
	"time"

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
