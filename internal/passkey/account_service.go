package passkey

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"

	"alphaomega/identitygateway/internal/audit"
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

// AccountRename writes the new name of one Passkey of the person the access
// token names.
//
// It demands no password. A rename destroys no Factor and changes no key: the
// worst a leaked access token does here is confuse the person who reads the
// list, and the removal below is where the proof belongs.
//
// Two Passkeys may share a name. Two devices a person calls "Phone" are that
// person's business, and the id tells them apart.
func (s *Service) AccountRename(
	ctx context.Context, tenantID string, who Principal, id, name string,
) error {
	s.log.Debug("rename a passkey from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	credID, err := decodeCredentialID(id)
	if err != nil {
		return err
	}

	// A name of spaces alone passes the request rules and trims to nothing. It
	// falls back to the word a registration uses, so no rename can leave the
	// person a row with no label on it.
	if name = strings.TrimSpace(name); name == "" {
		name = defaultName
	}

	if err := s.deps.Rename(ctx, tenantID, who.UserID, credID, name); err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.log.Error("rename the passkey",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", who.UserID), logger.Err(err))
		}
		return err
	}

	s.log.Info("renamed a passkey",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("credential_id", credentialID(credID)))
	return nil
}

// AccountRemove marks one Passkey of the person the access token names as
// removed, once they prove the password stored now.
//
// The password is checked before anything else. The access token carries no
// session identifier and the bearer guard reads no store, so this is the only
// proof the request can hold. Without it, a leaked access token strips the
// account of a Factor in one request. The TOTP removal demands the same proof.
//
// The removal is a mark and not a hard delete. The device keeps its key pair, so
// the row is what tells a later registration of that device that it may take the
// id back. A read never sees it again: every list narrows to the live rows.
//
// Removing the last Second Factor is allowed. The person then meets the
// enrolment step at the next sign-in, which is where a person with no Factor
// belongs.
//
// The password never reaches a log line.
func (s *Service) AccountRemove(
	ctx context.Context, tenantID string, who Principal, id, password string,
) error {
	s.log.Debug("remove a passkey from the portal",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))

	credID, err := decodeCredentialID(id)
	if err != nil {
		return err
	}

	if err := s.deps.VerifyPassword(ctx, tenantID, who.UserID, password); err != nil {
		return err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Delete(ctx, tenantID, who.UserID, credID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    who.UserID,
			Action:     audit.ActionMFAPasskeyRemoved,
			EntityType: audit.EntityUser,
			EntityID:   who.UserID,
			IP:         who.IP,
			UserAgent:  who.UserAgent,
			// The canonical spelling, and not the value from the address. A
			// client that padded the id would otherwise write a trail nobody can
			// match to the registration of the same device.
			Metadata:   map[string]any{"credential_id": credentialID(credID)},
		})
	})
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.log.Error("remove the passkey",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", who.UserID), logger.Err(err))
		}
		return err
	}

	s.log.Info("removed a passkey",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("credential_id", credentialID(credID)))
	return nil
}

// decodeCredentialID reads the id the browser and the list both spell in
// base64url, and answers the raw bytes the column holds.
//
// A value that is not base64url names no row, so it answers ErrNotFound and not
// a validation failure. The person is told the Passkey is gone, which is the
// truth for every id no row of theirs carries.
//
// The padding is trimmed first. The list answers the unpadded spelling, and a
// client that pads it names the same device.
func decodeCredentialID(id string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(id, "="))
	if err != nil || len(raw) == 0 {
		return nil, ErrNotFound
	}
	return raw, nil
}
