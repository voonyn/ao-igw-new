package utils

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RegistrableDomain answers the registrable domain, also called eTLD+1, of a
// hostname. It is the part somebody can buy: acme.co.uk for auth.acme.co.uk, and
// acme.com for auth.acme.com. The public suffix list carries the multi-part
// suffixes, so co.uk is one suffix and not two labels.
//
// It lives here because more than one domain reads it. A tenant refuses a
// hostname that does not share the registrable domain of the hosts it already
// serves, and the passkey ceremonies derive the WebAuthn RP ID from the same
// answer.
//
// A host that has no registrable domain answers the empty string. A development
// host such as localhost and a bare IP address both land there. A caller treats
// the empty answer as "cannot tell" and never as a refusal.
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil {
		return ""
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return etld1
}
