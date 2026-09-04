package http

import (
	"errors"
	"fmt"
	"testing"

	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/user"
	"alphaomega/identitygateway/internal/userfederation"
)

// TestDirectoryError covers the crossing between the LDAP client and the login
// session domain. It is the boundary that decides whether a failed sign-in reads
// as a wrong password or as a directory that did not answer, and the two must
// never be swapped: a directory outage answered as a wrong password would send
// every person of that tenant to the wrong helpdesk, and a wrong password
// answered as an outage would say which people the directory holds.
func TestDirectoryError(t *testing.T) {
	cases := []struct {
		name string
		from error
		want error
	}{
		{"a bind that proved the password", nil, nil},
		{"a wrong password", userfederation.ErrWrongPassword, session.ErrBadCredentials},
		{"no such entry", userfederation.ErrNoEntry, session.ErrBadCredentials},
		{"a disabled provider", userfederation.ErrDisabled, session.ErrFederationDisabled},
		{"a spent budget", userfederation.ErrTooManyProofs, session.ErrTooManyBinds},
		{"a directory that did not answer", userfederation.ErrDirectory, session.ErrFederationUnavailable},
		{"a budget nobody could read", userfederation.ErrProofUnavailable, session.ErrFederationUnavailable},
		{"a broken read of the row", errors.New("the database is down"), session.ErrFederationUnavailable},
		{
			"a provider that names no organization",
			userfederation.ErrNoOrganization, session.ErrFederationMisconfigured,
		},
		{
			"an entry that carries no username",
			userfederation.ErrNoUsername, session.ErrFederationMisconfigured,
		},
		// The three deliberate refusals of provision.go carry ErrDirectory, and
		// they keep the answer above. Each one is proved and refused, and a slug
		// of its own would say which people a tenant holds.
		{
			"a person an identity link names who cannot sign in",
			fmt.Errorf("%w: tenant t-1, user u-1", userfederation.ErrDirectory),
			session.ErrFederationUnavailable,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The client wraps every sentinel with context, so the crossing must
			// read the wrapped error and never compare it.
			from := c.from
			if from != nil {
				from = fmt.Errorf("bind as the person: %w", from)
			}

			got := directoryError(from)
			if c.want == nil {
				if got != nil {
					t.Fatalf("directoryError = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, c.want) {
				t.Fatalf("directoryError = %v, want %v", got, c.want)
			}
			// A configuration fault is permanent. It must borrow neither the
			// answer that tells the person to try again nor the one that tells
			// them the password was wrong, because no try of theirs can work
			// and the password they typed was proved.
			if c.want == session.ErrFederationMisconfigured {
				if errors.Is(got, session.ErrFederationUnavailable) {
					t.Error("a misconfigured directory reads as a directory outage")
				}
				if errors.Is(got, session.ErrBadCredentials) {
					t.Error("a misconfigured directory reads as a wrong password")
				}
			}
		})
	}
}

// TestAccountDirectoryError covers the crossing the portal re-proof takes. It is
// not the sign-in crossing above, and the difference is deliberate.
//
// The sign-in must not say which people a tenant holds, so it collapses a
// disabled directory and a spent budget into the refusal a wrong password gets.
// The portal caller already proved who they are with an access token, so there
// is nothing to hide, and only a password the directory refused reads as a wrong
// password.
//
// The portal also tells two kinds of failure apart. A directory that could not
// answer is transient, and the person tries again. A person whom no single
// directory entry proves is permanent, and no try of theirs can work.
//
// See docs/specs/0002-directory-sign-in.md.
func TestAccountDirectoryError(t *testing.T) {
	cases := []struct {
		name string
		from error
		want error
	}{
		{"a bind that proved the password", nil, nil},
		{"a wrong password", userfederation.ErrWrongPassword, user.ErrBadPassword},
		{"no single directory entry proves the person", userfederation.ErrNoEntry, user.ErrFederationNoAccount},
		{"a disabled provider", userfederation.ErrDisabled, user.ErrFederationUnavailable},
		{"a spent budget", userfederation.ErrTooManyProofs, user.ErrFederationUnavailable},
		{"a directory that did not answer", userfederation.ErrDirectory, user.ErrFederationUnavailable},
		{"a budget nobody could read", userfederation.ErrProofUnavailable, user.ErrFederationUnavailable},
		{"a broken read of the row", errors.New("the database is down"), user.ErrFederationUnavailable},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			from := c.from
			if from != nil {
				from = fmt.Errorf("bind as the person: %w", from)
			}

			got := accountDirectoryError(from)
			if c.want == nil {
				if got != nil {
					t.Fatalf("accountDirectoryError = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, c.want) {
				t.Fatalf("accountDirectoryError = %v, want %v", got, c.want)
			}
			if c.want == user.ErrFederationUnavailable && errors.Is(got, user.ErrBadPassword) {
				t.Error("a directory that could not prove the person reads as a wrong password")
			}
			// The permanent state must never borrow the transient answer. A 503
			// tells the person to try again, and no try of theirs can work.
			if c.want == user.ErrFederationNoAccount && errors.Is(got, user.ErrFederationUnavailable) {
				t.Error("a person whom no single directory entry proves reads as a directory outage")
			}
		})
	}
}
