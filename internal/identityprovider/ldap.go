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

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
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

// ErrDisabled reports a provider that is inactive or soft deleted. The two
// behave alike at sign-in: both refuse every person tied to them.
//
// The sign-in answers it with the slug an unknown identifier gets. A slug of its
// own would name every directory-owned person of the tenant for as long as the
// provider stays off, which is a permanent enumeration oracle at the password
// step. directory_disabled is the answer of the admin and the test route, where
// the caller is already authenticated. See docs/specs/0002-directory-sign-in.md.
var ErrDisabled = errors.New("the identity provider is disabled")

// ErrTooManyBinds reports an identifier that spent its whole bind budget. The
// directory is not dialled, and the caller waits out the window.
var ErrTooManyBinds = errors.New("too many directory binds")

// ErrBindUnavailable reports a bind budget nobody could read. Redis holds the
// whole counter, so a bind that ran without it would leave an outbound call into
// a customer network unmetered for as long as Redis is down.
//
// It is not ErrTooManyBinds. Both refuse, and the two mean different things: one
// says the caller guessed too often, and one says the gateway cannot meter the
// call at all.
var ErrBindUnavailable = errors.New("the bind budget is unavailable")

// bindLimit and bindWindow cap how many binds one identifier of one tenant
// drives.
//
// A bind is an outbound call into a customer network that any caller drives with
// a fresh partial token, and it is the only password guess this gateway meters.
// The number is small, because a person who types their own password needs a
// handful of tries and nobody needs thirty.
//
// Ceiling: an identifier key caps one person, and any caller can drive it. Two
// things follow. A spray across many identifiers still reaches the directory,
// and eleven wrong guesses lock one named person out of the directory sign-in
// for the rest of the window. The local password path has no budget, so this is
// the one credential of this gateway that a stranger can spend. The refusal
// answers what a wrong password answers, so the lockout says nothing about who
// the tenant holds.
//
// An IP key is the upgrade, and it is not built here. See
// docs/specs/0002-directory-sign-in.md.
//
// ponytail: two constants. Move them into a tenant policy row when a tenant asks
// for its own numbers.
const (
	bindLimit  = 10
	bindWindow = 15 * time.Minute
)

// bindKey names the bind budget of one identifier of one tenant.
//
// The identifier is personal data, so the key carries its digest and never the
// address itself. A Redis key is read by every operator who lists the keyspace,
// and the counter needs a stable name and nothing more.
func bindKey(tenantID, identifier string) string {
	return fmt.Sprintf("idp_binds:%s:%s", tenantID, aocrypto.Digest(identifier))
}

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

// The stages of one connection, in the order they run. A connection test names
// the stage that failed, so an administrator reads which value of the form is
// wrong instead of one message that covers four of them.
const (
	StageDial   = "dial"
	StageTLS    = "tls"
	StageBind   = "bind"
	StageSearch = "search"
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

	conn, _, err := dial(ctx, p)
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

// Prove proves one password against the directory a login session names. It is
// what the password step of the sign-in calls.
//
// Three steps run in this order, and the order is the point:
//
//  1. Read the provider. An inactive one and a soft-deleted one both refuse, and
//     neither dials anything.
//  2. Refuse an empty password. An unauthenticated bind proves nothing, so it
//     never reaches the wire, and a value that never reaches the wire must not
//     cost the person the budget a bind costs.
//  3. Spend one bind of the budget. Nothing above this line reaches the network,
//     so a refused provider and an empty password each cost none of it.
//  4. Bind.
//
// The budget is spent before the bind and not after it, because the budget
// bounds the outbound call and not the answer. A directory that does not answer
// therefore spends one bind, which the spec asks it not to: the only atomic
// primitive the cache offers is count-and-test on the way in, and a bind that
// spent nothing until it came back would leave a black-holing host reachable as
// often as a caller likes.
//
// ponytail: no refund. Give the cache a release primitive when a directory
// outage costing a person their budget is worth the second round trip.
//
// The typed password reaches Bind and nothing else. No log line of this method
// carries it, or the identifier, or the bind credential of the provider.
func (s *Service) Prove(
	ctx context.Context, tenantID, idpID, identifier, password string,
) (Identity, error) {
	s.log.Debug("prove a password against the directory",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID),
		logger.RequestID(ctx))

	row, err := s.deps.Find(ctx, tenantID, idpID)
	if errors.Is(err, ErrNotFound) {
		return Identity{}, fmt.Errorf("%w: tenant %s, provider %s", ErrDisabled, tenantID, idpID)
	}
	if err != nil {
		s.log.Error("read the identity provider of the sign-in",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.Err(err))
		return Identity{}, err
	}
	if row.State != StateActive {
		s.log.Warn("refused a sign-in against a disabled directory",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID))
		return Identity{}, fmt.Errorf("%w: tenant %s, provider %s", ErrDisabled, tenantID, idpID)
	}

	// The guard is in Bind as well, where it is what keeps an unauthenticated
	// bind off the wire. Here it is what keeps a value that costs the directory
	// nothing from costing the person their budget.
	if password == "" {
		return Identity{}, fmt.Errorf("%w: the password is empty", ErrWrongPassword)
	}

	if err := s.spendBind(ctx, tenantID, idpID, identifier); err != nil {
		return Identity{}, err
	}
	return s.Bind(ctx, row, identifier, password)
}

// spendBind spends one bind of the identifier's trailing-window budget, and
// refuses the sign-in when nothing is left.
//
// A cache failure refuses the bind. Redis is only a cache elsewhere in this
// gateway, and here it is the whole budget: a failure that let the bind through
// would turn the password step into a lever against a customer directory for as
// long as Redis is down. The password step carries no budget of its own, so
// there is nothing weaker to fall back to. See CLAUDE.md.
//
// ponytail: a refused read costs every directory-owned person their sign-in
// while Redis is down. The local password path keeps working, because it spends
// nothing.
func (s *Service) spendBind(ctx context.Context, tenantID, idpID, identifier string) error {
	allowed, err := s.deps.Allow(ctx, bindKey(tenantID, identifier), bindLimit, bindWindow)
	if err != nil {
		s.log.Error("read the directory bind budget",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.Err(err))
		return fmt.Errorf("%w: tenant %s", ErrBindUnavailable, tenantID)
	}
	if allowed {
		return nil
	}

	s.log.Warn("refused a directory bind over the budget",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID))
	return fmt.Errorf("%w: tenant %s", ErrTooManyBinds, tenantID)
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

// dial opens one connection to the first server that answers, and names the
// stage that failed when none of them did. The column holds a list because a
// directory runs on several controllers, so the list is tried in order and the
// last failure is the answer.
//
// One deadline covers the whole list, because timeout_ms bounds the request and
// not one server. Ceiling: a first server that accepts the connection and then
// answers nothing spends the whole budget, and the rest of the list is dialled
// with no time left. A refused server and an unreachable server both fail at
// once, which is the common failure, and the failover works there. A budget for
// each server is the upgrade, and it needs a second column to stay bounded.
func dial(ctx context.Context, p Provider) (*ldap.Conn, string, error) {
	if len(p.Servers) == 0 {
		return nil, StageDial, errors.New("the provider names no server")
	}

	timeout := time.Duration(p.TimeoutMS) * time.Millisecond
	if p.TimeoutMS <= 0 {
		timeout = defaultTimeoutMS * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	if held, ok := ctx.Deadline(); ok && held.Before(deadline) {
		deadline = held
	}

	stage := StageDial
	var err error
	for _, server := range p.Servers {
		var conn *ldap.Conn
		if conn, stage, err = dialOne(ctx, p, server, deadline); err == nil {
			return conn, "", nil
		}
	}
	return nil, stage, err
}

// dialOne opens one connection to one server string, runs the handshake the
// transport asks for, and names the stage that failed.
//
// The socket is opened in the clear for every transport, and TLS is a step of
// its own after it. LDAPS wraps the socket at once and StartTLS wraps it after
// the LDAP hello, so a certificate a client refuses reads as a TLS failure on
// both, and never as a directory that is down.
func dialOne(ctx context.Context, p Provider, server string, deadline time.Time) (*ldap.Conn, string, error) {
	addr, host, err := address(p.Mode, server)
	if err != nil {
		return nil, StageDial, err
	}

	// The TLS of the row is read before the socket opens, so a root_ca that
	// holds no valid PEM refuses without dialling anything.
	var cfg *tls.Config
	if p.Mode != ModePlain {
		if cfg, err = tlsConfig(p, host); err != nil {
			return nil, StageTLS, err
		}
	}

	raw, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, StageDial, fmt.Errorf("dial %s: %w", addr, err)
	}

	// One deadline on the socket bounds the whole exchange. The handshake, the
	// search and both binds fail the moment it passes, so a directory that stops
	// answering halfway never hangs the request.
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return nil, StageDial, err
	}

	if p.Mode == ModeLDAPS {
		secure := tls.Client(raw, cfg)
		if err := secure.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, StageTLS, fmt.Errorf("handshake with %s: %w", addr, err)
		}
		raw = secure
	}

	conn := ldap.NewConn(raw, p.Mode == ModeLDAPS)
	conn.Start()

	if p.Mode == ModeStartTLS {
		if err := conn.StartTLS(cfg); err != nil {
			conn.Close()
			return nil, StageTLS, fmt.Errorf("start TLS with %s: %w", addr, err)
		}
	}
	return conn, "", nil
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

// classFilter names every object class the row requires, and no identifier:
//
//	(&(objectClass=person)(objectClass=user))
//
// The connection test searches with it. A test counts the people the base holds
// and proves nothing about one of them, so it names nobody.
func classFilter(p Provider) string {
	parts := make([]string, 0, len(p.UserObjectClasses))
	for _, class := range p.UserObjectClasses {
		parts = append(parts, fmt.Sprintf("(objectClass=%s)", ldap.EscapeFilter(class)))
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
