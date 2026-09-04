package http

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/user"
	"alphaomega/identitygateway/internal/userfederation"
)

// The read that names the Directory of one person, and the username the bind
// searches on.
//
// Federation Resolution answers it. Neither the password_hash column nor the
// Federation Link can: case 1 routes a person whose email domain a live active
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
		func(_ context.Context, tenantID, userID, identifier, email string) (string, error) {
			asked = append(asked, tenantID, userID, identifier, email)
			return "idp-one", nil
		},
	)

	federationID, username, err := directory(t.Context(), reproveTenantID, reproveUserID)
	if err != nil {
		t.Fatalf("directoryOf: %v", err)
	}
	if federationID != "idp-one" {
		t.Errorf("the read named %q, want the provider the resolver named", federationID)
	}
	if username != "alice" {
		t.Errorf("the read named the username %q, want the one the person holds", username)
	}

	want := []string{reproveTenantID, reproveUserID, "", "alice@corp.example"}
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

	federationID, _, err := directory(t.Context(), reproveTenantID, reproveUserID)
	if err != nil {
		t.Fatalf("directoryOf: %v", err)
	}
	if federationID != "" {
		t.Errorf("the read named %q, want no provider at all", federationID)
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

// TestDirectoryReProverRefusals proves the two refusals the re-proof makes
// before any bind runs, and the state each one names.
//
// The empty username is the point. A directory owns the person, the row carries
// no username, and the bind has no search value. No retry mends that, so the
// answer is the permanent one and never `federation_unavailable`. See
// .scratch/directory-sign-in/issues/25.
func TestDirectoryReProverRefusals(t *testing.T) {
	cases := []struct {
		name         string
		federationID string
		username     string
		want         error
	}{
		{"no single directory", "", "alice", user.ErrFederationNoAccount},
		{"a person who holds no username", "idp-one", "", user.ErrFederationNoAccount},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reprove := directoryReProver(
				func(context.Context, userfederation.Attempt, string) (userfederation.Identity, error) {
					t.Error("the bind ran on a re-proof the guard must refuse")
					return userfederation.Identity{}, nil
				},
				logger.New(),
			)

			err := reprove(t.Context(),
				reproveTenantID, c.federationID, reproveUserID, c.username, "the typed password")
			if !errors.Is(err, c.want) {
				t.Errorf("the re-proof answered %v, want %v", err, c.want)
			}
		})
	}
}

// TestOnePasswordProofResolvesTheDirectoryOnce proves the fix of ticket 28. One
// portal password check reads the person row once and runs Federation Resolution
// once.
//
// The predicate that decides the credential already names the Directory and the
// username, so the re-proof resolves nothing. It binds on the answer that read
// found.
func TestOnePasswordProofResolvesTheDirectoryOnce(t *testing.T) {
	var finds, resolves int
	directory := directoryOf(
		func(context.Context, string, string) (user.User, error) {
			finds++
			return claimedPerson(), nil
		},
		func(context.Context, string, string, string, string) (string, error) {
			resolves++
			return "idp-one", nil
		},
	)
	account := user.NewAccountService(user.AccountDeps{
		Credential: func(context.Context, string, string) (user.User, error) {
			return claimedPerson(), nil
		},
		Directory: directory,
		ProveDirectory: directoryReProver(
			func(context.Context, userfederation.Attempt, string) (userfederation.Identity, error) {
				return userfederation.Identity{}, nil
			},
			logger.New(),
		),
		Log: logger.New(),
	})

	actor := user.Actor{TenantID: reproveTenantID, UserID: reproveUserID}
	if err := account.VerifyPassword(t.Context(), actor, "the typed password"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}

	if finds != 1 {
		t.Errorf("one password check read the person row %d times, want 1", finds)
	}
	if resolves != 1 {
		t.Errorf("one password check ran Federation Resolution %d times, want 1", resolves)
	}
}

// TestDirectoryReProverBindsOnTheUsername proves the one path that binds. The
// username the person holds reaches the bind as the search value, and the typed
// password travels with it.
func TestDirectoryReProverBindsOnTheUsername(t *testing.T) {
	var asked userfederation.Attempt
	var askedPassword string
	reprove := directoryReProver(
		func(_ context.Context, a userfederation.Attempt, password string) (userfederation.Identity, error) {
			asked, askedPassword = a, password
			return userfederation.Identity{}, nil
		},
		logger.New(),
	)

	err := reprove(t.Context(),
		reproveTenantID, "idp-one", reproveUserID, "alice", "the typed password")
	if err != nil {
		t.Fatalf("a proved re-proof answered %v, want nil", err)
	}

	want := userfederation.Attempt{
		TenantID: reproveTenantID, FederationID: "idp-one", UserID: reproveUserID, Identifier: "alice",
	}
	if asked != want {
		t.Errorf("the bind was asked %+v, want %+v", asked, want)
	}
	if askedPassword != "the typed password" {
		t.Errorf("the bind was asked the password %q, want the typed one", askedPassword)
	}
}
