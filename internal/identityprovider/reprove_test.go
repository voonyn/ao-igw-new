package identityprovider

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/platform/logger"
)

// The portal re-proof, which names the directory from the links of the person
// and never from a typed identifier.
//
// Two link counts refuse and never dial: none, and more than one. Neither names
// a single directory to prove against, so neither can prove a password.

// reproveService builds a service whose link read answers idpIDs, and whose
// provider read answers row. It records the provider each bind named.
func reproveService(idpIDs []string, row Provider, dialled *[]string) *Service {
	return NewService(Deps{
		Linked: func(context.Context, string, string) ([]string, error) {
			return idpIDs, nil
		},
		Find: func(_ context.Context, _, idpID string) (Provider, error) {
			*dialled = append(*dialled, idpID)
			return row, nil
		},
		Log: logger.New(),
	})
}

// TestProveOwnerNamesTheOneDirectoryTheLinkHolds proves the routing. The one
// live active link of the person names the provider the bind reads.
//
// The provider row answers disabled, so the test stops at the state check and
// dials nothing. What it measures is which provider the re-proof named.
func TestProveOwnerNamesTheOneDirectoryTheLinkHolds(t *testing.T) {
	var dialled []string
	svc := reproveService([]string{"idp-one"}, Provider{State: StateInactive}, &dialled)

	err := svc.ProveOwner(t.Context(), "tenant-one", "user-one", "alice", "a-password")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("ProveOwner answered %v, want %v", err, ErrDisabled)
	}
	if len(dialled) != 1 || dialled[0] != "idp-one" {
		t.Errorf("the re-proof read %v, want the one provider the link holds", dialled)
	}
}

// TestProveOwnerRefusesWhenNoSingleDirectoryOwnsThePerson proves both refusals.
// A person with no live active link and a person with two both answer ErrNoEntry,
// and neither read reaches a provider row.
func TestProveOwnerRefusesWhenNoSingleDirectoryOwnsThePerson(t *testing.T) {
	cases := map[string][]string{
		"no link":   {},
		"two links": {"idp-one", "idp-two"},
	}

	for name, idpIDs := range cases {
		t.Run(name, func(t *testing.T) {
			var dialled []string
			svc := reproveService(idpIDs, Provider{State: StateActive}, &dialled)

			err := svc.ProveOwner(t.Context(), "tenant-one", "user-one", "alice", "a-password")
			if !errors.Is(err, ErrNoEntry) {
				t.Fatalf("ProveOwner answered %v, want %v", err, ErrNoEntry)
			}
			if len(dialled) != 0 {
				t.Errorf("the re-proof read %v, want no provider at all", dialled)
			}
		})
	}
}
