package passkey

import (
	"context"

	"github.com/go-webauthn/webauthn/protocol"

	"alphaomega/identitygateway/internal/platform/logger"
)

// The portal keys its ceremony on the subject of the access token. No login
// session is in flight there, so the person themselves is the holder, and no
// identifier is minted for the ceremony.

// AccountRegisterStart hands the person the registration options their browser
// passes to navigator.credentials.create().
//
// It demands no proof beyond the access token. A registration creates a Factor
// and destroys none, and the finish below proves the device before any row is
// written.
func (s *Service) AccountRegisterStart(
	ctx context.Context, tenantID, host, origin string, who Principal,
) (*protocol.CredentialCreation, error) {
	s.log.Debug("start a passkey registration from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	return s.registerStart(ctx, tenantID, host, origin, who)
}

// AccountRegisterFinish verifies the answer of the browser and stores the
// Passkey of the person the access token names.
//
// The answer is the object the browser produced, passed through whole. Nothing
// between the device and this call picks a field out of it, because every field
// is part of what the signature covers.
func (s *Service) AccountRegisterFinish(
	ctx context.Context, tenantID, host, origin, name string, who Principal, answer []byte,
) (Credential, error) {
	s.log.Debug("finish a passkey registration from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	return s.registerFinish(ctx, tenantID, host, origin, name, who, answer)
}

// AccountList answers the live Passkeys of the person the access token names.
//
// It is one bounded whole list. A person holds at most ten Passkeys, so nothing
// here pages.
func (s *Service) AccountList(
	ctx context.Context, tenantID string, who Principal,
) ([]Credential, error) {
	s.log.Debug("list the passkeys from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	rows, err := s.deps.List(ctx, tenantID, who.UserID)
	if err != nil {
		s.log.Error("list the passkeys",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, err
	}
	return rows, nil
}
