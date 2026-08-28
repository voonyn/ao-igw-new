package totp

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	rfc6238 "github.com/pquerna/otp/totp"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
)

// period is the width of one TOTP time step, in seconds. RFC 6238 names 30, and
// every Authenticator uses it.
const period = 30

// verifyOpts is how a code is read. The values are the defaults of RFC 6238, and
// they are written out because an Authenticator cannot be asked what it used.
//
// Skew is 0. The window this gateway allows is applied below, in verify, which
// tries the current step and the one before it. The library's own skew reaches
// forward as well, and a step that has not arrived yet is a code nobody can have
// read off a phone.
var verifyOpts = rfc6238.ValidateOpts{
	Period:    period,
	Skew:      0,
	Digits:    otp.DigitsSix,
	Algorithm: otp.AlgorithmSHA1,
}

// mint returns a new shared secret and the provisioning URI that carries it into
// an Authenticator.
//
// issuerHost names the tenant, and label names the person. Both reach the screen
// of the Authenticator, so an account of one tenant is not confused with an
// account of another.
func mint(issuerHost, label string) (secret, uri string, err error) {
	key, err := rfc6238.Generate(rfc6238.GenerateOpts{
		Issuer:      issuerHost,
		AccountName: label,
		Period:      period,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("mint a totp secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// verify reports the time step one code proves, and false when it proves none.
//
// The current step and the one before it are both tried, so a phone whose clock
// drifts by a few seconds still works. A wider window is a wider target for a
// person guessing six digits.
//
// The code never reaches a log line, here or in any caller.
func verify(secret, code string, now time.Time) (int64, bool) {
	step := now.Unix() / period
	for _, candidate := range []int64{step, step - 1} {
		at := time.Unix(candidate*period, 0).UTC()
		if ok, err := rfc6238.ValidateCustom(code, secret, at, verifyOpts); err == nil && ok {
			return candidate, true
		}
	}
	return 0, false
}

// issuerHost is the host of one issuer, which is how a provisioning URI names
// the tenant. The issuer is on every request, so no extra read is needed.
//
// An issuer that parses to no host falls back to the issuer as written. The URI
// then still carries a name, and a blank label is what must never happen.
func issuerHost(issuer string) string {
	if u, err := url.Parse(issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return issuer
}

// crockford is the Crockford base32 alphabet: the ten digits and the letters,
// less I, L, O and U. A person reading a printed code cannot confuse the letters
// that are left with 1, 0 or V.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// recoveryCodeCount is how many codes one set holds.
const recoveryCodeCount = 10

// recoveryCodeLength is how many characters one code holds. Ten characters of
// this alphabet carry 50 bits, so a code is not guessable.
const recoveryCodeLength = 10

// recoveryCodeGroup is how many characters one printed group holds. A code is
// shown in two groups, which is what makes ten characters readable off paper.
const recoveryCodeGroup = 5

// newRecoveryCodes mints one set of Recovery Codes.
//
// shown is what the person is given, once. digests is what the database stores.
// The plaintext code is never stored, and it never reaches a log line.
func newRecoveryCodes() (shown, digests []string, err error) {
	shown = make([]string, 0, recoveryCodeCount)
	digests = make([]string, 0, recoveryCodeCount)

	for range recoveryCodeCount {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		shown = append(shown, grouped(code))
		digests = append(digests, digestCode(code))
	}
	return shown, digests, nil
}

// newRecoveryCode returns one code in its canonical form.
//
// The alphabet holds 32 characters and a byte holds 256 values, so masking the
// low five bits draws each character with the same chance. A modulo of a
// non-power-of-two alphabet would not.
func newRecoveryCode() (string, error) {
	buf := make([]byte, recoveryCodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes for a recovery code: %w", err)
	}

	out := make([]byte, recoveryCodeLength)
	for i, b := range buf {
		out[i] = crockford[b&31]
	}
	return string(out), nil
}

// grouped renders one canonical code the way it is presented: two groups of
// five, separated by a hyphen.
func grouped(code string) string {
	if len(code) != recoveryCodeLength {
		return code
	}
	return code[:recoveryCodeGroup] + "-" + code[recoveryCodeGroup:]
}

// canonical is the one spelling of a Recovery Code that a digest is taken of.
//
// It upper-cases, drops every character outside the alphabet, and folds the
// three Crockford substitutions. A person who types the printed hyphen, or a
// lower-case l for a 1, redeems the code they hold.
func canonical(code string) string {
	var b strings.Builder
	b.Grow(len(code))

	for _, r := range strings.ToUpper(code) {
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if strings.ContainsRune(crockford, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// digestCode is what the database stores for one Recovery Code: a SHA-256 digest
// of the canonical spelling. A Recovery Code is high-entropy, so a fast digest is
// the right one. This is not a password.
func digestCode(code string) string {
	return aocrypto.Digest(canonical(code))
}
