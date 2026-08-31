package passkey

import (
	"context"
	"errors"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The console reads and revokes the Passkeys of somebody else. It never
// registers one: a Factor belongs to the person who holds the device, and no
// privilege puts a key pair on an operator's desk.
//
// Two of the three ceremony steps therefore have no console counterpart. This
// file holds the whole administrative surface, and it is a read and a revoke.

// Authorizer refuses an operator who may not run this call on this person.
//
// It is a gate of the user domain, handed over as a function value. This module
// imports neither the user domain nor the login session domain, so the router
// composes the crossing, the way it composes the second-factor reset.
type Authorizer func(ctx context.Context, tenantID, actorID, userID string) error

// AdminDeps is the console side of the module: the same two repository calls the
// portal uses, behind the role check of the user domain.
//
// There is no ceremony store, no origin list, and no guessing budget. None of
// the three belongs to a read or a revoke, and a console that held them could
// run a registration.
type AdminDeps struct {
	// AuthorizeRead decides the list. It is the read gate of the user domain,
	// the one the account record and the two-factor state of the same screen
	// already ran, so an operator who reads the account reads the devices on it.
	AuthorizeRead Authorizer

	// AuthorizeWrite decides the revoke. It is the narrower gate, and it takes
	// the organization of the account into account, so an operator who reads the
	// list is still refused the removal of a device.
	AuthorizeWrite Authorizer

	List   CredentialLister
	Delete CredentialRemover

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AdminService serves the console. It is separate from Service because it shares
// none of the ceremony state, and a half-filled ceremony service would be a
// registration surface nobody meant to mount.
type AdminService struct {
	deps AdminDeps
	log  logger.Logger
}

func NewAdminService(deps AdminDeps) *AdminService {
	return &AdminService{deps: deps, log: deps.Log}
}

// List answers the live Passkeys of one person to an operator who administers
// this tenant.
//
// It runs the read gate and not the write gate. An operator who reads the
// account record of that person answers their support call about a lost device,
// and the device name and the last-used date are what name the device.
//
// It is one bounded whole list. A person holds at most ten Passkeys, so nothing
// here pages. A person who holds none reads an empty list, which is the normal
// state of an account that never registered a device.
func (s *AdminService) List(
	ctx context.Context, tenantID string, who Principal, userID string,
) ([]Credential, error) {
	s.log.Debug("list the passkeys of a user from the console",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("target_user_id", userID), logger.RequestID(ctx))

	if err := s.deps.AuthorizeRead(ctx, tenantID, who.UserID, userID); err != nil {
		return nil, err
	}

	rows, err := s.deps.List(ctx, tenantID, userID)
	if err != nil {
		s.log.Error("list the passkeys of a user",
			logger.String("tenant_id", tenantID),
			logger.String("target_user_id", userID), logger.Err(err))
		return nil, err
	}
	return rows, nil
}

// Revoke marks one Passkey of one person as removed, on the word of an operator.
//
// It demands no password. The operator does not hold the person's, and the role
// check is the whole proof of the request: the console reset beside it destroys
// every Factor on the same authority.
//
// Every other Factor of that person survives. A lost laptop costs the person one
// device, not the authenticator they still hold, which is what tells this apart
// from the reset.
//
// The removal is a mark and not a hard delete. The device keeps its key pair, so
// the row is what tells a later registration of that device that it may take the
// id back.
func (s *AdminService) Revoke(
	ctx context.Context, tenantID string, who Principal, userID, id string,
) error {
	s.log.Debug("revoke a passkey of a user from the console",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("target_user_id", userID), logger.RequestID(ctx))

	if err := s.deps.AuthorizeWrite(ctx, tenantID, who.UserID, userID); err != nil {
		return err
	}

	credID, err := decodeCredentialID(id)
	if err != nil {
		return err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Delete(ctx, tenantID, userID, credID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    who.UserID,
			Action:     audit.ActionUserPasskeyRevoked,
			EntityType: audit.EntityUser,
			EntityID:   userID,
			IP:         who.IP,
			UserAgent:  who.UserAgent,
			// The canonical spelling, and not the value from the address. A
			// client that padded the id would otherwise write a trail nobody can
			// match to the registration of the same device.
			//
			// The id and nothing else. It is a public handle every assertion
			// sends in the clear, and the public key beside it never leaves the
			// table.
			Metadata: map[string]any{"credential_id": credentialID(credID)},
		})
	})
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.log.Error("revoke the passkey of a user",
				logger.String("tenant_id", tenantID),
				logger.String("target_user_id", userID), logger.Err(err))
		}
		return err
	}

	s.log.Info("revoked a passkey of a user",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("target_user_id", userID),
		logger.String("credential_id", credentialID(credID)))
	return nil
}
