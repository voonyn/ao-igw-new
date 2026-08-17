package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/utils"
)

// SourceStatic is the source type of a mapper that carries its value instead of
// reading one. It is stored and written here, and the claims service does not
// release it yet.
//
// SourceMembership, type 3, is stored by the schema and is neither written nor
// released. No field of this API mints one.
const SourceStatic = 4

// MaxMappersPerScope bounds one scope.
//
// Every mapper of a granted scope is resolved on every token build and on every
// UserInfo read, so an unbounded set is a cost the tenant pays per request. The
// seeded profile scope carries six, so the limit leaves a tenant far more room
// than the standard claims need.
const MaxMappersPerScope = 50

// MaxSourceValueBytes bounds the value of one static mapper. The value is copied
// into every token the scope is granted on, so a large one inflates every token
// of the tenant.
const MaxSourceValueBytes = 4096

// ErrMapperNotFound reports that the tenant holds no live claim mapper with that
// id.
var ErrMapperNotFound = errors.New("claim mapper not found")

// ErrClaimTaken reports a claim the scope already releases. One scope releases
// one claim once: a second rule for the same key would make the value of the
// claim depend on the order the rules were read in.
var ErrClaimTaken = errors.New("the scope already releases that claim")

// ErrProtectedClaim reports a claim name this API does not write.
//
// A protocol claim, such as sub or exp, is built by the token issuer. A mapper
// naming one would be overwritten, or it would corrupt a token every relying
// party checks.
//
// A trust claim, such as email_verified, states what the gateway verified. It is
// released by the mapper the migration seeded and by nothing else, because a
// rule an operator can point at any column would let a tenant assert a
// verification that never happened.
var ErrProtectedClaim = errors.New("that claim name is reserved")

// ErrLimitExceeded reports too many claim mappers on one scope, or a static
// value that is too large.
var ErrLimitExceeded = errors.New("the limit of this scope is exceeded")

// protectedClaims names every claim this API refuses to write. See
// ErrProtectedClaim for why each group is here.
var protectedClaims = map[string]bool{
	// The registered claims of a JWT, and the OpenID Connect claims the token
	// issuer builds.
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true,
	"iat": true, "jti": true, "azp": true, "nonce": true, "auth_time": true,
	"at_hash": true, "c_hash": true, "s_hash": true, "acr": true, "amr": true,
	"sid": true, "scope": true, "client_id": true, "typ": true,

	// The trust claims. Each states what the gateway verified.
	"email_verified": true, "phone_number_verified": true,
}

// The claim mapper reads and writes. Each one is a function value, so the logic
// is testable without a database.
type (
	// MapperRowLister reads every live claim mapper of one scope.
	MapperRowLister func(ctx context.Context, tenantID, scopeID string) ([]ClaimMapperRow, error)

	// MapperFinderByID reads one live claim mapper of a tenant by its id.
	MapperFinderByID func(ctx context.Context, tenantID, id string) (ClaimMapperRow, error)

	// MapperCounter counts the live claim mappers of one scope.
	MapperCounter func(ctx context.Context, tenantID, scopeID string) (int, error)

	// MapperInserter writes one new claim mapper.
	MapperInserter func(ctx context.Context, row ClaimMapperRow) error

	// MapperUpdater writes the fields of one claim mapper.
	MapperUpdater func(ctx context.Context, row ClaimMapperRow) error

	// MapperDeleter marks one claim mapper of a tenant deleted.
	MapperDeleter func(ctx context.Context, tenantID, id string) error
)

// ListMappers answers every claim the named scope releases. The list is bounded
// by MaxMappersPerScope, so it is not paged.
func (s *ScopeAdminService) ListMappers(
	ctx context.Context, a AdminActor, scopeID string,
) ([]MapperView, error) {
	s.log.Debug("list the claim mappers",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", scopeID))

	if err := s.authorize(ctx, a, "list the claim mappers"); err != nil {
		return nil, err
	}

	// The scope is read first, so a scope of another tenant answers the way a
	// scope nobody holds answers, and never with an empty list.
	if _, err := s.deps.FindScope(ctx, a.TenantID, scopeID); err != nil {
		if errors.Is(err, ErrScopeNotFound) {
			return nil, err
		}
		return nil, s.fail(a, "read the scope", err)
	}

	rows, err := s.deps.ListMappers(ctx, a.TenantID, scopeID)
	if err != nil {
		return nil, s.fail(a, "list the claim mappers", err)
	}

	views := make([]MapperView, 0, len(rows))
	for _, row := range rows {
		views = append(views, mapperView(row))
	}
	return views, nil
}

// CreateMapper writes one new claim mapper on the named scope.
func (s *ScopeAdminService) CreateMapper(
	ctx context.Context, a AdminActor, scopeID string, body MapperBody,
) (MapperView, error) {
	s.log.Debug("create a claim mapper",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", scopeID))

	if err := s.authorize(ctx, a, "create a claim mapper"); err != nil {
		return MapperView{}, err
	}
	if protectedClaims[body.ClaimName] {
		return MapperView{}, s.refuseClaim(a, body.ClaimName)
	}
	value, err := staticValue(body)
	if err != nil {
		return MapperView{}, err
	}

	row := ClaimMapperRow{
		ID:            utils.NewUUIDv7(),
		TenantID:      a.TenantID,
		ScopeID:       scopeID,
		ClaimName:     body.ClaimName,
		SourceType:    body.SourceType,
		SourceKey:     body.SourceKey,
		SourceValue:   value,
		InIDToken:     body.InIDToken,
		InUserInfo:    body.InUserInfo,
		InAccessToken: body.InAccessToken,
	}
	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.deps.FindScope(ctx, a.TenantID, scopeID); err != nil {
			return err
		}

		count, err := s.deps.CountMappers(ctx, a.TenantID, scopeID)
		if err != nil {
			return err
		}
		if count >= MaxMappersPerScope {
			return fmt.Errorf("%w: %s holds %d claims", ErrLimitExceeded, scopeID, count)
		}
		if err := s.freeClaim(ctx, a.TenantID, scopeID, body.ClaimName, ""); err != nil {
			return err
		}

		if err := s.deps.InsertMapper(ctx, row); err != nil {
			return err
		}
		return s.mapperEvent(ctx, a, audit.ActionMapperCreated, row)
	})
	if err != nil {
		return MapperView{}, s.mapperFail(a, "create a claim mapper", err)
	}

	s.log.Info("created a claim mapper",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", scopeID))
	return mapperView(row), nil
}

// UpdateMapper writes one claim mapper and answers the row as it then stands.
//
// The stored claim name is checked as well as the new one. A seeded trust claim
// is not rewritten to read a column an operator chose, so the rule that releases
// it stays as the migration wrote it.
func (s *ScopeAdminService) UpdateMapper(
	ctx context.Context, a AdminActor, id string, body MapperBody,
) (MapperView, error) {
	s.log.Debug("write a claim mapper",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("mapper_id", id))

	if err := s.authorize(ctx, a, "write a claim mapper"); err != nil {
		return MapperView{}, err
	}
	if protectedClaims[body.ClaimName] {
		return MapperView{}, s.refuseClaim(a, body.ClaimName)
	}
	value, err := staticValue(body)
	if err != nil {
		return MapperView{}, err
	}

	var out ClaimMapperRow
	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		row, err := s.deps.FindMapper(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if protectedClaims[row.ClaimName] {
			return fmt.Errorf("%w: %s", ErrProtectedClaim, row.ClaimName)
		}
		if body.ClaimName != row.ClaimName {
			if err := s.freeClaim(ctx, a.TenantID, row.ScopeID, body.ClaimName, row.ID); err != nil {
				return err
			}
		}

		row.ClaimName = body.ClaimName
		row.SourceType = body.SourceType
		row.SourceKey = body.SourceKey
		row.SourceValue = value
		row.InIDToken = body.InIDToken
		row.InUserInfo = body.InUserInfo
		row.InAccessToken = body.InAccessToken

		if err := s.deps.UpdateMapper(ctx, row); err != nil {
			return err
		}
		out = row
		return s.mapperEvent(ctx, a, audit.ActionMapperUpdated, row)
	})
	if err != nil {
		return MapperView{}, s.mapperFail(a, "write a claim mapper", err)
	}

	s.log.Info("wrote a claim mapper",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("mapper_id", id))
	return mapperView(out), nil
}

// DeleteMapper marks one claim mapper of the tenant deleted. The scope stops
// releasing the claim on the next token it is granted on.
func (s *ScopeAdminService) DeleteMapper(ctx context.Context, a AdminActor, id string) error {
	s.log.Debug("delete a claim mapper",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("mapper_id", id))

	if err := s.authorize(ctx, a, "delete a claim mapper"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		row, err := s.deps.FindMapper(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if protectedClaims[row.ClaimName] {
			return fmt.Errorf("%w: %s", ErrProtectedClaim, row.ClaimName)
		}

		if err := s.deps.DeleteMapper(ctx, a.TenantID, id); err != nil {
			return err
		}
		return s.mapperEvent(ctx, a, audit.ActionMapperDeleted, row)
	})
	if err != nil {
		return s.mapperFail(a, "delete a claim mapper", err)
	}

	s.log.Info("deleted a claim mapper",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("mapper_id", id))
	return nil
}

// freeClaim reports whether the scope can release the claim. keep names the
// mapper that is allowed to hold it already, so a write that does not rename the
// claim passes.
func (s *ScopeAdminService) freeClaim(
	ctx context.Context, tenantID, scopeID, claim, keep string,
) error {
	rows, err := s.deps.ListMappers(ctx, tenantID, scopeID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ClaimName == claim && row.ID != keep {
			return fmt.Errorf("%w: %s releases %s", ErrClaimTaken, scopeID, claim)
		}
	}
	return nil
}

// mapperEvent records one claim mapper change. The scope and the claim travel in
// the metadata, because the trail is searched by the words an operator names and
// a deleted mapper leaves nothing else to read.
func (s *ScopeAdminService) mapperEvent(
	ctx context.Context, a AdminActor, action audit.Action, row ClaimMapperRow,
) error {
	return s.deps.Audit.Record(ctx, audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityClaimMapper,
		EntityID:   row.ID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
		Metadata:   map[string]any{"scope_id": row.ScopeID, "claim_name": row.ClaimName},
	})
}

// mapperFail answers a refusal by name, and logs anything else once.
func (s *ScopeAdminService) mapperFail(a AdminActor, what string, err error) error {
	switch {
	case errors.Is(err, ErrScopeNotFound), errors.Is(err, ErrMapperNotFound),
		errors.Is(err, ErrClaimTaken), errors.Is(err, ErrProtectedClaim),
		errors.Is(err, ErrLimitExceeded):
		return err
	default:
		return s.fail(a, what, err)
	}
}

// refuseClaim logs and answers a write of a reserved claim name.
func (s *ScopeAdminService) refuseClaim(a AdminActor, claim string) error {
	s.log.Warn("refused a reserved claim name",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("claim_name", claim))
	return fmt.Errorf("%w: %s", ErrProtectedClaim, claim)
}

// staticValue encodes the value of a static mapper. Every other source type
// reads a key and carries no value, so the column stays null.
func staticValue(body MapperBody) (string, error) {
	if body.SourceType != SourceStatic || body.SourceValue == nil {
		return "", nil
	}

	value, err := json.Marshal(body.SourceValue)
	if err != nil {
		return "", fmt.Errorf("%w: the static value is not JSON", ErrLimitExceeded)
	}
	if len(value) > MaxSourceValueBytes {
		return "", fmt.Errorf("%w: the static value is %d bytes", ErrLimitExceeded, len(value))
	}
	return string(value), nil
}
