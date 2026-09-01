package http

import (
	"errors"
	"fmt"
	"testing"

	"alphaomega/identitygateway/internal/identityprovider"
	"alphaomega/identitygateway/internal/session"
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
		{"a wrong password", identityprovider.ErrWrongPassword, session.ErrBadCredentials},
		{"no such entry", identityprovider.ErrNoEntry, session.ErrBadCredentials},
		{"a disabled provider", identityprovider.ErrDisabled, session.ErrDirectoryDisabled},
		{"a spent budget", identityprovider.ErrTooManyBinds, session.ErrTooManyBinds},
		{"a directory that did not answer", identityprovider.ErrDirectory, session.ErrDirectoryUnavailable},
		{"a budget nobody could read", identityprovider.ErrBindUnavailable, session.ErrDirectoryUnavailable},
		{"a broken read of the row", errors.New("the database is down"), session.ErrDirectoryUnavailable},
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
		})
	}
}
