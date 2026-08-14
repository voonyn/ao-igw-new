package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Password verification outcomes. Callers MUST treat ErrPasswordMismatch and
// ErrMalformedHash identically when reporting to end users (a generic
// "invalid credentials") — the distinction exists only for server-side logging
// and metrics, never for the response, so a stored-hash defect is not
// distinguishable from a wrong password by an attacker.
var (
	// ErrPasswordMismatch means the hash is well-formed but the password is wrong.
	ErrPasswordMismatch = errors.New("crypto: password mismatch")
	// ErrPasswordTooLong means the input exceeds bcrypt's 72-byte ceiling; bcrypt
	// would silently truncate, so we reject instead of comparing a prefix.
	ErrPasswordTooLong = errors.New("crypto: password exceeds 72 bytes")
	// ErrMalformedHash means the stored hash could not be parsed as bcrypt
	// (corrupt, wrong algorithm, empty). Distinct from a mismatch on purpose.
	ErrMalformedHash = errors.New("crypto: malformed password hash")
)

// DefaultBcryptCost is the industry recommended default (old repo:
// cryptokey.hashCost). Lowering it invalidates nothing — bcrypt stores the cost
// in the hash — but every credential minted after the change gets weaker.
const DefaultBcryptCost = 12

// MaxPasswordBytes is bcrypt's hard input ceiling. Inputs longer than this are
// rejected rather than silently truncated.
const MaxPasswordBytes = 72

// HashPassword returns a bcrypt hash of plain, suitable for storing in
// user_humans.password_hash. The cost is the industry recommended default.
//
// bcrypt silently truncates input beyond 72 bytes; callers using it for
// arbitrary-length user passwords should reject longer inputs upstream. The
// 24-char OneTimePassword is well within the limit.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("crypto: password is empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), DefaultBcryptCost)
	if err != nil {
		return "", fmt.Errorf("crypto: hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword compares a candidate password against a stored bcrypt hash. It
// always performs the full bcrypt computation when the hash is well-formed, so
// its timing does not depend on whether the password matched — only on the
// hash's cost factor. Returns:
//
//   - nil                  on a correct password;
//   - ErrPasswordMismatch  when the hash is valid but the password is wrong;
//   - ErrPasswordTooLong   when plain exceeds MaxPasswordBytes (rejected, not truncated);
//   - ErrMalformedHash     when hash is not a parseable bcrypt hash.
//
// For enumeration-safe login the caller equalizes timing across the
// user-exists / user-missing branches by running this against a dummy hash of
// the same cost when no real user is bound.
func VerifyPassword(hash, plain string) error {
	if len(plain) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return ErrPasswordMismatch
	default:
		// Unparseable / wrong-version / too-short hash: a stored-credential
		// defect, not a wrong password. Kept distinct for logging only.
		return fmt.Errorf("%w: %v", ErrMalformedHash, err)
	}
}
