package authpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrWeakPassword reports a password that the resolved policy of the level
// refuses.
//
// The answer never names the rule that failed. A caller told "too short" learns
// the minimum length, and a caller told "denied word" learns the deny list. One
// refusal for every rule discloses neither.
var ErrWeakPassword = errors.New("password does not meet the policy")

// CheckPassword reports whether plain meets one resolved policy. It reads no
// database, so every rule is testable on its own.
//
// Length is counted in runes. A person who types eight accented characters meets
// a minimum of eight.
//
// The ceiling is counted in bytes, because that is what bcrypt refuses above. A
// password of 72 accented characters is 144 bytes, so a rune bound on the DTO
// would admit a password the hash step cannot store. It is refused here, with
// the refusal every other rule answers, and the write never reaches bcrypt.
//
// A deny word matches anywhere in the password, and case does not matter. That is
// what the list is for: a tenant that denies its own product name means to refuse
// "acme2024" as much as "acme".
//
// PwCheckBreach is not read here. This deployment builds no breach client, and
// Enforce is where that is reported.
//
// The password reaches no log line, here or anywhere below.
func CheckPassword(view View, plain string) error {
	if utf8.RuneCountInString(plain) < view.PwMinLength {
		return ErrWeakPassword
	}
	if len(plain) > crypto.MaxPasswordBytes {
		return ErrWeakPassword
	}
	if passwordClasses(plain) < view.PwMinClasses {
		return ErrWeakPassword
	}

	lowered := strings.ToLower(plain)
	for _, word := range view.PwDenyList {
		if word == "" {
			continue
		}
		if strings.Contains(lowered, strings.ToLower(word)) {
			return ErrWeakPassword
		}
	}
	return nil
}

// passwordClasses counts the character classes one password draws from: lower
// case, upper case, digits, and everything else. PwMinClasses is how many of the
// four a password must use.
func passwordClasses(plain string) int {
	var lower, upper, digit, other bool
	for _, r := range plain {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}

	count := 0
	for _, present := range []bool{lower, upper, digit, other} {
		if present {
			count++
		}
	}
	return count
}

// Enforce resolves the policy of one level and checks plain against it.
//
// It is the function value every password write takes, so a domain that writes a
// password imports nothing from this package. An empty orgID reads the tenant
// default.
//
// A failed policy read is logged here and nowhere else. The caller receives the
// error as an opaque value it cannot classify — that is the price of the
// function value — so this is the last layer that can name the tenant and the
// organization the read was for.
func (s *Service) Enforce(ctx context.Context, tenantID, orgID, plain string) error {
	s.log.Debug("check a password against the auth policy",
		logger.String("tenant_id", tenantID),
		logger.String("org_id", orgID), logger.RequestID(ctx))

	view, err := s.resolved(ctx, tenantID, orgID)
	if err != nil {
		s.log.Error("read the auth policy to check a password",
			logger.String("tenant_id", tenantID),
			logger.String("org_id", orgID), logger.Err(err))
		return fmt.Errorf("read the auth policy of %s/%s: %w", tenantID, orgID, err)
	}

	// The breach toggle is a per-tenant column the console can set, and this
	// deployment builds no breach client. Refusing every password would be worse
	// than the check being absent, so the write proceeds and the gap is named.
	if view.PwCheckBreach {
		s.log.Warn("the auth policy asks for a breach check and no breach client is built; the check is skipped",
			logger.String("tenant_id", tenantID), logger.String("org_id", orgID))
	}
	return CheckPassword(view, plain)
}
