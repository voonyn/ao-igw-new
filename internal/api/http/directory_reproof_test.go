package http

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/user"
)

// The read that names the Directory of one person, and the username the bind
// searches on.
//
// Provider Resolution answers it. Neither the password_hash column nor the
// Identity Link can: case 1 routes a person whose email domain a live active
// provider claims, and the claim writes no row, so that person keeps their hash
// and holds no link. A re-proof that read either one would shut the four
// destructive portal routes on a person who signs in every day.
//
// See .scratch/directory-sign-in/issues/21.

const (
	reproveTenantID = "33333333-3333-3333-3333-333333333333"
	reproveUserID   = "44444444-4444-4444-4444-444444444444"
)

// claimedPerson is the person a domain claim routes: a local account, with the
// username and the hash it always had, whose email domain a provider claims.
func claimedPerson() user.User {
	return user.User{
		ID:           reproveUserID,
		TenantID:     reproveTenantID,
		Username:     "alice",
		Email:        "alice@corp.example",
		PasswordHash: "$2a$10$the.hash.the.claim.retired",
	}
}

// TestDirectoryOfAsksTheResolverAboutThePerson proves what the read asks. The
// email address of the person reaches the resolver, the typed identifier is
// empty, and the answer of the resolver travels back whole.
func TestDirectoryOfAsksTheResolverAboutThePerson(t *testing.T) {
	var asked []string
	directory := directoryOf(
		func(context.Context, string, string) (user.User, error) {
			return claimedPerson(), nil
		},
		func(_ context.Context, tenantID, identifier, userID, email string) (string, error) {
			asked = append(asked, tenantID, identifier, userID, email)
			return "idp-one", nil
		},
	)

	idpID, username, err := directory(t.Context(), reproveTenantID, reproveUserID)
	if err != nil {
		t.Fatalf("directoryOf: %v", err)
	}
	if idpID != "idp-one" {
		t.Errorf("the read named %q, want the provider the resolver named", idpID)
	}
	if username != "alice" {
		t.Errorf("the read named the username %q, want the one the person holds", username)
	}

	want := []string{reproveTenantID, "", reproveUserID, "alice@corp.example"}
	if len(asked) != len(want) {
		t.Fatalf("the resolver was asked %v, want %v", asked, want)
	}
	for i := range want {
		if asked[i] != want[i] {
			t.Errorf("the resolver was asked %v, want %v", asked, want)
			break
		}
	}
}

// TestDirectoryOfAnswersALocalPersonWithNoProvider proves the other answer. A
// person no provider proves reads an empty id, and the local compare proves
// them, which is what the sign-in does for them.
func TestDirectoryOfAnswersALocalPersonWithNoProvider(t *testing.T) {
	directory := directoryOf(
		func(context.Context, string, string) (user.User, error) {
			return claimedPerson(), nil
		},
		func(context.Context, string, string, string, string) (string, error) {
			return "", nil
		},
	)

	idpID, _, err := directory(t.Context(), reproveTenantID, reproveUserID)
	if err != nil {
		t.Fatalf("directoryOf: %v", err)
	}
	if idpID != "" {
		t.Errorf("the read named %q, want no provider at all", idpID)
	}
}

// TestDirectoryOfCarriesABrokenRead proves the rule the sign-in path holds: a
// read that broke stops the request. Both reads are measured, because a fall
// back to the local compare would prove a person against the hash a domain
// claim retired.
func TestDirectoryOfCarriesABrokenRead(t *testing.T) {
	broken := errors.New("the read failed")

	brokenPerson := directoryOf(
		func(context.Context, string, string) (user.User, error) {
			return user.User{}, broken
		},
		func(context.Context, string, string, string, string) (string, error) {
			t.Error("the resolver ran on a person the read could not name")
			return "idp-one", nil
		},
	)
	if _, _, err := brokenPerson(t.Context(), reproveTenantID, reproveUserID); !errors.Is(err, broken) {
		t.Errorf("a broken person read answered %v, want %v", err, broken)
	}

	brokenResolve := directoryOf(
		func(context.Context, string, string) (user.User, error) {
			return claimedPerson(), nil
		},
		func(context.Context, string, string, string, string) (string, error) {
			return "", broken
		},
	)
	if _, _, err := brokenResolve(t.Context(), reproveTenantID, reproveUserID); !errors.Is(err, broken) {
		t.Errorf("a broken resolver read answered %v, want %v", err, broken)
	}
}
