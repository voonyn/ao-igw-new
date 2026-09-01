package identityprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNoEntry reports that the search matched no single entry: none at all, or
// more than one. Two entries is a failure and never a pick, because the second
// bind would prove the password of whichever entry the directory listed first.
var ErrNoEntry = errors.New("the search matched no single entry")

// ErrWrongPassword reports that the directory refused the password the person
// typed. It is the one outcome of this package that means a wrong password.
var ErrWrongPassword = errors.New("the directory refused the password")

// ErrDirectory reports that the directory did not answer: a dial failure, a
// timeout, a TLS failure, or a bind failure of the service credential. None of
// those is a credential failure, and the caller answers directory_unavailable.
var ErrDirectory = errors.New("the directory did not answer")

// defaultTimeoutMS bounds a row that carries no timeout. The column defaults to
// 5000 and the body requires a value, so this floor catches only a row written
// around both. A deadline of zero would refuse every bind of that provider.
const defaultTimeoutMS = 5000

// The port each transport dials when the server string names none. A plain bind
// and a StartTLS bind share the plaintext port, and LDAPS dials its own.
const (
	portPlain = "389"
	portLDAPS = "636"
)

// Identity is one directory account, read by the attribute names the provider
// row carries.
//
// ExternalID is the stable id of the directory, objectGUID in Active Directory.
// The Identity Link stores it, so a username the directory later changes never
// orphans the person.
//
// The three name fields are optional. A provider that maps no display name
// answers an empty display name, and that is not a failure.
type Identity struct {
	DN          string
	ExternalID  string
	Username    string
	Email       string
	FirstName   string
	LastName    string
	DisplayName string
}

// Bind proves one password against one directory, and answers the account it
// belongs to.
//
// The sequence is fixed: dial by mode, bind as the service account, run one
// search under the base, then bind a second time as the entry that was found,
// with the password the person typed. The second bind is what proves the
// password. Nothing else does.
//
// The typed password reaches the second bind and nothing else. No log line of
// this package carries it, or the bind password of the provider, or the DN of
// the bind account.
func (s *Service) Bind(ctx context.Context, p Provider, identifier, password string) (Identity, error) {
	s.log.Debug("bind against the directory",
		logger.String("tenant_id", p.TenantID), logger.String("idp_id", p.ID),
		logger.RequestID(ctx))

	// An empty password is an unauthenticated bind, which most directories
	// answer with success. It proves nothing, so it never reaches the wire.
	if password == "" {
		return Identity{}, fmt.Errorf("%w: the password is empty", ErrWrongPassword)
	}
	if p.BindDN == "" || p.BindPassword == "" {
		return Identity{}, fmt.Errorf("%w: provider %s carries no bind credential", ErrDirectory, p.ID)
	}
	// A row that maps no filter builds a filter that names no identifier, and
	// that search matches whichever person the base holds. The columns are
	// nullable and only the body requires them, so the guard runs here too.
	if len(p.UserObjectClasses) == 0 || len(p.UserFilters) == 0 {
		return Identity{}, fmt.Errorf("%w: provider %s carries no user filter", ErrDirectory, p.ID)
	}

	conn, err := dial(ctx, p)
	if err != nil {
		return Identity{}, s.unavailable(p, "dial the directory", err)
	}
	defer conn.Close()

	if err := conn.Bind(p.BindDN, p.BindPassword); err != nil {
		return Identity{}, s.unavailable(p, "bind as the service account", err)
	}

	entry, err := search(conn, p, identifier)
	if err != nil {
		if errors.Is(err, ErrNoEntry) {
			s.log.Debug("the directory matched no single entry",
				logger.String("tenant_id", p.TenantID), logger.String("idp_id", p.ID),
				logger.RequestID(ctx))
			return Identity{}, err
		}
		return Identity{}, s.unavailable(p, "search the directory", err)
	}

	person := identityOf(p, entry)
	// Without the stable id the Identity Link holds no key, so a bind that
	// proved the password would tie the person to nobody.
	if person.ExternalID == "" {
		return Identity{}, fmt.Errorf("%w: the entry carries no %s", ErrNoEntry, p.AttrID)
	}

	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Identity{}, fmt.Errorf("%w: provider %s", ErrWrongPassword, p.ID)
		}
		return Identity{}, s.unavailable(p, "bind as the person", err)
	}

	s.log.Debug("bound against the directory",
		logger.String("tenant_id", p.TenantID), logger.String("idp_id", p.ID),
		logger.RequestID(ctx))
	return person, nil
}

// search runs one search under the base of the provider, and answers the single
// entry it matched.
func search(conn *ldap.Conn, p Provider, identifier string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		searchBase(p),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, p.TimeoutMS/1000, false,
		searchFilter(p, identifier),
		attributes(p), nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		// A filter that matches many people trips the size limit. That is the
		// same failure as two entries, and never a pick.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, fmt.Errorf("%w: the search matched more than one entry", ErrNoEntry)
		}
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("%w: the search matched %d entries", ErrNoEntry, len(res.Entries))
	}
	return res.Entries[0], nil
}

// dial opens one connection to the first server that answers. The column holds a
// list because a directory runs on several controllers, so the list is tried in
// order and the last failure is the answer.
//
// One deadline covers the whole list, because timeout_ms bounds the request and
// not one server. Ceiling: a first server that accepts the connection and then
// answers nothing spends the whole budget, and the rest of the list is dialled
// with no time left. A refused server and an unreachable server both fail at
// once, which is the common failure, and the failover works there. A budget for
// each server is the upgrade, and it needs a second column to stay bounded.
func dial(ctx context.Context, p Provider) (*ldap.Conn, error) {
	if len(p.Servers) == 0 {
		return nil, errors.New("the provider names no server")
	}

	timeout := time.Duration(p.TimeoutMS) * time.Millisecond
	if p.TimeoutMS <= 0 {
		timeout = defaultTimeoutMS * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	if held, ok := ctx.Deadline(); ok && held.Before(deadline) {
		deadline = held
	}

	var err error
	for _, server := range p.Servers {
		var conn *ldap.Conn
		if conn, err = dialOne(ctx, p, server, deadline); err == nil {
			return conn, nil
		}
	}
	return nil, err
}

// dialOne opens one connection to one server string, and runs StartTLS when the
// transport asks for it.
func dialOne(ctx context.Context, p Provider, server string, deadline time.Time) (*ldap.Conn, error) {
	addr, host, err := address(p.Mode, server)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Deadline: deadline}
	var raw net.Conn
	if p.Mode == ModeLDAPS {
		cfg, err := tlsConfig(p, host)
		if err != nil {
			return nil, err
		}
		if raw, err = (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr); err != nil {
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
	} else {
		if raw, err = dialer.DialContext(ctx, "tcp", addr); err != nil {
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
	}

	// One deadline on the socket bounds the whole exchange. The search and both
	// binds fail the moment it passes, so a directory that stops answering
	// halfway never hangs the request.
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return nil, err
	}

	conn := ldap.NewConn(raw, p.Mode == ModeLDAPS)
	conn.Start()

	if p.Mode == ModeStartTLS {
		cfg, err := tlsConfig(p, host)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if err := conn.StartTLS(cfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("start TLS with %s: %w", addr, err)
		}
	}
	return conn, nil
}

// address answers the address one server string dials, and the host name the
// certificate must carry. A string that names no port takes the port of its
// transport.
func address(mode int, server string) (addr, host string, err error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s cannot be read", ErrServerScheme, server)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("%w: %s names no host", ErrServerScheme, server)
	}

	port := u.Port()
	if port == "" {
		port = portPlain
		if mode == ModeLDAPS {
			port = portLDAPS
		}
	}
	return net.JoinHostPort(host, port), host, nil
}

// tlsConfig is the TLS of one provider. Certificate checks are on and the
// minimum version is pinned, the way cmd/server.go pins the Redis connection.
// The egress precedent of this repository, internal/di/di.go, configures no TLS
// at all, and it is not copied here.
//
// root_ca, when it is set, is the only authority this provider trusts: the PEM
// replaces the system store instead of joining it, which is what redisTLSConfig
// does with its own CA bundle.
func tlsConfig(p Provider, host string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if p.RootCA == "" {
		return cfg, nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(p.RootCA)) {
		return nil, fmt.Errorf("%w: root_ca holds no valid PEM certificate", ErrDirectory)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// searchBase is the subtree the search runs under. user_base, when it is set, is
// a subtree of base_dn such as ou=people, so it is prefixed and never replaces
// the base.
func searchBase(p Provider) string {
	if p.UserBase == "" {
		return p.BaseDN
	}
	return p.UserBase + "," + p.BaseDN
}

// searchFilter builds the one filter the search runs. Every object class is
// required, and the identifier matches any one of the filter attributes:
//
//	(&(objectClass=person)(objectClass=user)(|(uid=alice)(mail=alice)))
//
// Every value is escaped, so a hostile identifier cannot close a parenthesis and
// widen the search to every person of the directory.
func searchFilter(p Provider, identifier string) string {
	safe := ldap.EscapeFilter(identifier)

	parts := make([]string, 0, len(p.UserObjectClasses)+1)
	for _, class := range p.UserObjectClasses {
		parts = append(parts, fmt.Sprintf("(objectClass=%s)", ldap.EscapeFilter(class)))
	}

	matches := make([]string, 0, len(p.UserFilters))
	for _, attr := range p.UserFilters {
		matches = append(matches, fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(attr), safe))
	}
	if match := join("|", matches); match != "" {
		parts = append(parts, match)
	}
	return join("&", parts)
}

// join wraps a list of filters in one operator. One filter is answered as it
// stands, because a directory reads (&(x)) and refuses (&).
func join(op string, parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return "(" + op + strings.Join(parts, "") + ")"
	}
}

// attributes are the names the row maps, and no others. A row that maps no first
// name asks the directory for nothing, and the answer carries an empty first
// name.
func attributes(p Provider) []string {
	mapped := []string{p.AttrID, p.AttrUsername, p.AttrEmail, p.AttrFirstName, p.AttrLastName, p.AttrDisplayName}

	names := make([]string, 0, len(mapped))
	for _, name := range mapped {
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// identityOf reads one entry by the attribute names the provider row carries.
func identityOf(p Provider, entry *ldap.Entry) Identity {
	return Identity{
		DN:          entry.DN,
		ExternalID:  stableID(entry, p.AttrID),
		Username:    value(entry, p.AttrUsername),
		Email:       value(entry, p.AttrEmail),
		FirstName:   value(entry, p.AttrFirstName),
		LastName:    value(entry, p.AttrLastName),
		DisplayName: value(entry, p.AttrDisplayName),
	}
}

// value reads one attribute by the name the row carries. A name the row does not
// map, and a value the entry does not hold, both answer an empty string.
func value(entry *ldap.Entry, name string) string {
	if name == "" {
		return ""
	}
	return entry.GetAttributeValue(name)
}

// stableID reads the id attribute. Active Directory answers objectGUID as raw
// binary, which no VARCHAR column holds, so a value that is not text is hex
// encoded. The encoding is fixed, so the same account reads as the same id on
// every later bind.
func stableID(entry *ldap.Entry, name string) string {
	if name == "" {
		return ""
	}

	raw := entry.GetRawAttributeValue(name)
	if len(raw) == 0 {
		return ""
	}

	text := string(raw)
	if utf8.ValidString(text) && strings.IndexFunc(text, control) < 0 {
		return text
	}
	return hex.EncodeToString(raw)
}

// control reports one character that no printable id holds. Sixteen random bytes
// are valid text often enough to matter, so the text test alone would let a
// binary id reach the column now and then.
func control(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// unavailable logs one directory that did not answer, and returns ErrDirectory.
// The line names the provider, and never the bind DN, the bind password, or the
// password the person typed.
func (s *Service) unavailable(p Provider, what string, err error) error {
	s.log.Warn("the directory did not answer",
		logger.String("tenant_id", p.TenantID),
		logger.String("idp_id", p.ID),
		logger.String("what", what),
		logger.Err(err))
	return fmt.Errorf("%w: %s: %w", ErrDirectory, what, err)
}
