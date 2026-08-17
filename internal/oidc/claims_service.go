package oidc

import (
	"context"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
)

// The claim mapper source types. A mapper reads a standard attribute of the
// person, or one key of the per-user attribute bag.
//
// Types 3 (membership) and 4 (static) are stored but not released yet, so a
// mapper that names one is skipped.
const (
	SourceStandard = 1
	SourceBag      = 2
)

// ClaimMapper releases one claim from one scope. The claim name is the emitted
// key, and the two flags name the places the value reaches.
//
// The mapper carries no scope name, because the finder already filtered by the
// requested scopes. in_access_token is not read: no claim rides the access
// token.
type ClaimMapper struct {
	ClaimName  string
	SourceType int
	SourceKey  string
	InIDToken  bool
	InUserInfo bool
}

// UserProfile is the claim source of one person: the standard attributes, and
// the custom attribute bag.
type UserProfile struct {
	Username      string
	DisplayName   string
	FirstName     string
	LastName      string
	Email         string
	EmailVerified bool
	Locale        string
	UpdatedAt     time.Time
	Attributes    map[string]any
}

// Claims is one person's claims, split by the place each one reaches.
type Claims struct {
	IDToken  map[string]any
	UserInfo map[string]any
}

// MapperFinder reads the live mappers of the requested scopes.
type MapperFinder func(ctx context.Context, tenantID string, scopes []string) ([]ClaimMapper, error)

// ProfileFinder reads the claim source of one person.
type ProfileFinder func(ctx context.Context, tenantID, userID string) (UserProfile, error)

// ClaimsDeps is the database side of the claims service.
type ClaimsDeps struct {
	Mappers MapperFinder
	Profile ProfileFinder
	Log     logger.Logger
}

// ClaimsService turns the tenant's claim mappers into the claims of one
// person.
type ClaimsService struct {
	deps ClaimsDeps
	log  logger.Logger
}

func NewClaimsService(deps ClaimsDeps) *ClaimsService {
	return &ClaimsService{deps: deps, log: deps.Log}
}

// Claims reads the mappers of the requested scopes and resolves each one
// against the person. A mapper whose value is absent releases nothing.
func (s *ClaimsService) Claims(
	ctx context.Context, tenantID, userID string, scopes []string,
) (Claims, error) {
	s.log.Debug("resolve claims",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID))

	mappers, err := s.deps.Mappers(ctx, tenantID, scopes)
	if err != nil {
		s.log.Error("read claim mappers",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return Claims{}, err
	}
	if len(mappers) == 0 {
		return Claims{}, nil
	}

	profile, err := s.deps.Profile(ctx, tenantID, userID)
	if err != nil {
		s.log.Error("read claim source",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", userID),
			logger.Err(err))
		return Claims{}, err
	}

	out := Claims{IDToken: map[string]any{}, UserInfo: map[string]any{}}
	for _, mapper := range mappers {
		value, ok := resolveClaim(mapper, profile)
		if !ok {
			continue
		}
		if mapper.InIDToken {
			out.IDToken[mapper.ClaimName] = value
		}
		if mapper.InUserInfo {
			out.UserInfo[mapper.ClaimName] = value
		}
	}

	s.log.Debug("resolved claims",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID))
	return out, nil
}

// resolveClaim reads the value one mapper names. The second answer is false
// when the mapper names a source this release does not read, a key the
// whitelist does not hold, or a value the person does not carry.
func resolveClaim(mapper ClaimMapper, profile UserProfile) (any, bool) {
	switch mapper.SourceType {
	case SourceStandard:
		return standardClaim(mapper.SourceKey, profile)
	case SourceBag:
		value, ok := profile.Attributes[mapper.SourceKey]
		return value, ok && value != nil
	default:
		return nil, false
	}
}

// standardClaim reads one standard attribute of the person. The source key is
// never interpolated into SQL: it selects a case of this whitelist, and a key
// outside the list releases nothing.
func standardClaim(key string, profile UserProfile) (any, bool) {
	switch key {
	case "name":
		return text(profile.DisplayName)
	case "given_name":
		return text(profile.FirstName)
	case "family_name":
		return text(profile.LastName)
	case "preferred_username":
		return text(profile.Username)
	case "locale":
		return text(profile.Locale)
	case "email":
		return text(profile.Email)
	case "email_verified":
		return profile.EmailVerified, profile.Email != ""
	case "updated_at":
		if profile.UpdatedAt.IsZero() {
			return nil, false
		}
		return profile.UpdatedAt.Unix(), true
	default:
		return nil, false
	}
}

// text releases a string attribute the person carries. An empty column is an
// absent value, so the claim is omitted.
func text(value string) (any, bool) {
	return value, value != ""
}
