package crypto

import (
	"errors"
	"strings"
	"testing"
)

func TestVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	tests := []struct {
		name  string
		hash  string
		plain string
		want  error // nil means success
	}{
		{name: "correct password", hash: hash, plain: "correct horse battery staple", want: nil},
		{name: "wrong password", hash: hash, plain: "wrong", want: ErrPasswordMismatch},
		{name: "empty candidate", hash: hash, plain: "", want: ErrPasswordMismatch},
		{name: "malformed hash", hash: "not-a-bcrypt-hash", plain: "whatever", want: ErrMalformedHash},
		{name: "empty hash", hash: "", plain: "whatever", want: ErrMalformedHash},
		{name: "over 72 bytes rejected", hash: hash, plain: strings.Repeat("a", 73), want: ErrPasswordTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPassword(tt.hash, tt.plain)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("VerifyPassword() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifyPassword() = %v, want %v", err, tt.want)
			}
		})
	}
}

// A 72-byte password is the boundary and must still be compared, not rejected.
func TestVerifyPassword_BoundaryLength(t *testing.T) {
	pw := strings.Repeat("a", 72)
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(hash, pw); err != nil {
		t.Fatalf("72-byte password should verify, got %v", err)
	}
	if err := VerifyPassword(hash, strings.Repeat("a", 73)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("73-byte password want ErrPasswordTooLong, got %v", err)
	}
}
