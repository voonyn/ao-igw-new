package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrAmbiguous reports that no single Identity Provider proves one sign-in. Two
// live active providers of the tenant give it, and so do two Identity Links that
// both take a typed password.
//
// The slug of this refusal is provider_ambiguous. No answer of the sign-in
// carries it, and no route maps it: the identifier step answers the same thing
// in every case, so the caller falls back to the local password compare, which
// refuses the password step the way an unknown identifier already does. A
// gateway that picked one of the two instead would send the password of one
// customer to the server of another. See docs/adr/0013.
var ErrAmbiguous = errors.New("no single identity provider proves this sign-in")

// The reads the resolver composes its answer from. Each one is a function value,
// so the logic is testable without a database.
type (
	// DomainFinder reads the live active provider that claims one email domain.
	// A domain nobody claims returns ErrNotFound.
	DomainFinder func(ctx context.Context, tenantID, domain string) (string, error)

	// LinkedFinder reads the live active providers that take a typed password
	// and that one person holds an Identity Link with.
	LinkedFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// ActiveFinder reads every live active provider of one tenant.
	ActiveFinder func(ctx context.Context, tenantID string) ([]string, error)

	// PersonFinder reports whether the tenant holds any account for one
	// identifier, whatever its state and soft-deleted rows included.
	PersonFinder func(ctx context.Context, tenantID, identifier string) (bool, error)
)

// ResolverDeps is the database side of the resolver.
//
// Active covers both levels together, tenant-wide rows and organization rows,
// because the case that reads it knows no organization yet.
//
// Held is a second read of the person, and it filters neither the state nor the
// soft delete. FindByIdentifier filters state = active inside the query, so a
// deactivated, locked, or soft-deleted person reads as absent there, and a
// sign-in that took that for "nobody" would create a brand-new person on the
// first bind.
type ResolverDeps struct {
	DomainOwner DomainFinder
	Linked      LinkedFinder
	Active      ActiveFinder
	Held        PersonFinder

	Log logger.Logger
}

// Resolver names the Identity Provider that proves one sign-in.
//
// It is a type of its own, beside the console service. Resolution runs on the
// sign-in path, where there is no actor, no audit row, and no transaction, so it
// carries the four reads that answer the question and nothing else.
type Resolver struct {
	deps ResolverDeps
	log  logger.Logger
}

func NewResolver(deps ResolverDeps) *Resolver {
	return &Resolver{deps: deps, log: deps.Log}
}

// Resolve names the Identity Provider that proves one sign-in, and answers an
// empty id when the local password compare proves it. It is what the identifier
// step takes.
//
// A refusal is not an error here. Which of the two refusals ran says whether the
// identifier named a real person, so a caller that answered them apart would be
// the enumeration oracle the identifier step must not be. Both answer the local
// compare, which refuses the password step the way an unknown identifier does.
//
// A read that broke is an error, and it stops the request. That is what a broken
// read of the person already does at this step, so the answer is the same for
// everybody, and a sign-in never falls back to a local password hash that a
// domain claim was meant to take out of service.
//
// userID and email are the person the identifier step named, and both are empty
// when that read named nobody.
func (r *Resolver) Resolve(ctx context.Context, tenantID, userID, identifier, email string) (string, error) {
	idpID, err := r.resolve(ctx, tenantID, userID, identifier, email)
	if errors.Is(err, ErrAmbiguous) {
		return "", nil
	}
	return idpID, err
}

// resolve runs the four cases and refuses with ErrAmbiguous.
//
// userID and email are the person FindByIdentifier named, and both are empty
// when that read missed. Four cases run in this order:
//
//  1. A live active provider claims the domain of the person. Two forms carry
//     that domain, and case 1 reads both: the identifier they typed, and the
//     email address the tenant holds for them. A person who types their
//     username carries the claim in the second form alone, and a claim a person
//     steps around by typing another form of their own identifier is no guard
//     rail. Either match answers that provider. It outranks every case below,
//     including a person who holds a local password, which is what makes a
//     domain claim a guard rail of its own. See
//     docs/specs/0002-directory-sign-in.md.
//  2. No domain match, and the person holds exactly one Identity Link with a
//     provider that takes a typed password. That provider answers.
//  3. No domain match, and the person holds no such link. The local compare
//     answers, as it does today.
//  4. No domain match and no account at all. One live active provider of the
//     tenant answers, and two or more refuse.
//
// A person who holds no link and no password hash reaches case 3 and is refused
// by the password step, which is what happens to them today.
//
// The email form of case 1 carries a ceiling. The bind searches the directory on
// the string the person typed, ldap.go:273, so a provider whose user filter
// matches the email attribute alone refuses a typed username that a claim on the
// email form routed here. That filter has to match every form a tenant lets
// people type in any case, because a typed email meets the same wall today.
//
// The identifier and the email address are personal data, so neither reaches a
// log line.
func (r *Resolver) resolve(ctx context.Context, tenantID, userID, identifier, email string) (string, error) {
	r.log.Debug("resolve the identity provider",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	for _, domain := range domainsOf(identifier, email) {
		idpID, err := r.deps.DomainOwner(ctx, tenantID, domain)
		if err == nil {
			return idpID, nil
		}
		if !errors.Is(err, ErrNotFound) {
			r.log.Error("read the provider that claims the domain",
				logger.String("tenant_id", tenantID), logger.Err(err))
			return "", err
		}
	}

	if userID != "" {
		linked, err := r.deps.Linked(ctx, tenantID, userID)
		if err != nil {
			r.log.Error("read the identity links of the person",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", userID), logger.Err(err))
			return "", err
		}
		return r.sole(tenantID, linked)
	}

	// An account the tenant holds in any state is not case 4. Without this read
	// a soft-deleted person whose directory account still lives would be created
	// again by their next sign-in, because uq_username maps a NULL deleted_at to
	// an epoch and leaves the username free.
	held, err := r.deps.Held(ctx, tenantID, identifier)
	if err != nil {
		r.log.Error("read whether the tenant holds the account",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return "", err
	}
	if held {
		return "", nil
	}

	active, err := r.deps.Active(ctx, tenantID)
	if err != nil {
		r.log.Error("read the active identity providers",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return "", err
	}
	return r.sole(tenantID, active)
}

// sole answers the one provider a list holds. An empty list answers the local
// password compare, and two or more answer ErrAmbiguous.
//
// Neither the log line nor the error names which case refused, and neither
// carries the count. Both of those would say whether the identifier named a real
// person, because case 2 counts links and case 4 counts providers.
func (r *Resolver) sole(tenantID string, idpIDs []string) (string, error) {
	switch len(idpIDs) {
	case 0:
		return "", nil
	case 1:
		return idpIDs[0], nil
	}

	r.log.Warn("refused a sign-in that no single identity provider proves",
		logger.String("tenant_id", tenantID))
	return "", fmt.Errorf("%w: tenant %s", ErrAmbiguous, tenantID)
}

// domainsOf answers the domains case 1 reads, in the order it reads them. A
// form that carries no domain, and a second form that repeats the first, add
// nothing: a person who typed their own email address drives one read.
func domainsOf(forms ...string) []string {
	var domains []string
	for _, form := range forms {
		domain := emailDomain(form)
		if domain != "" && !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return domains
}

// emailDomain answers the domain one identifier carries, trimmed and lowercased,
// and an empty string for a bare username.
//
// The claim column holds a lowercased host, because Body.apply lowercases every
// domain on write, so the match is case insensitive on both sides. The last @ is
// the separator, because the local part of an address can hold one too.
func emailDomain(identifier string) string {
	trimmed := strings.ToLower(strings.TrimSpace(identifier))
	at := strings.LastIndex(trimmed, "@")
	if at < 0 {
		return ""
	}
	return trimmed[at+1:]
}
