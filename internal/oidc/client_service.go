package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrPairwiseSubject reports a client row that asks for a pairwise subject.
// Only a public subject is implemented, and answering a pairwise client with a
// public subject would hand it the identifier every other client already has.
var ErrPairwiseSubject = errors.New("pairwise subject is not supported")

// ErrClientSecretMissing reports that the client stores no secret. A public
// client authenticates with PKCE alone, so an empty stored value never matches.
var ErrClientSecretMissing = errors.New("client has no secret")

// ClientService serves the clients of one tenant to the protocol engine.
type ClientService struct {
	repo *ClientRepository
	log  logger.Logger
}

func NewClientService(repo *ClientRepository, log logger.Logger) *ClientService {
	return &ClientService{repo: repo, log: log}
}

// FindByClientID reads one client of one tenant as the protocol engine sees it.
func (s *ClientService) FindByClientID(ctx context.Context, tenantID, clientID string) (goidc.Client, error) {
	row, err := s.repo.FindByClientID(ctx, tenantID, clientID)
	if err != nil {
		return goidc.Client{}, err
	}
	client, err := toGoidcClient(row)
	if err != nil {
		s.log.Error("map client row",
			logger.String("tenant_id", tenantID),
			logger.String("client_id", clientID),
			logger.Err(err))
		return goidc.Client{}, err
	}
	return client, nil
}

// VerifyClientSecret compares a presented client secret against the bcrypt hash
// the row stores. The signature matches goidc.VerifyClientSecretFunc, so the
// provider build installs it directly.
func VerifyClientSecret(_ context.Context, stored, presented string) error {
	if stored == "" || presented == "" {
		return ErrClientSecretMissing
	}
	return aocrypto.VerifyPassword(stored, presented)
}

// toGoidcClient maps one client row into the client the protocol engine reads.
// An empty subject type means public, which is the only type in this step.
func toGoidcClient(row Client) (goidc.Client, error) {
	subject := goidc.SubIdentifierType(row.SubjectType)
	if subject == "" {
		subject = goidc.SubIdentifierPublic
	}
	if subject != goidc.SubIdentifierPublic {
		return goidc.Client{}, fmt.Errorf("%w: client %s", ErrPairwiseSubject, row.ClientID)
	}

	grants := make([]goidc.GrantType, 0, len(row.GrantTypes))
	for _, grant := range row.GrantTypes {
		grants = append(grants, goidc.GrantType(grant))
	}
	responses := make([]goidc.ResponseType, 0, len(row.ResponseTypes))
	for _, response := range row.ResponseTypes {
		responses = append(responses, goidc.ResponseType(response))
	}

	return goidc.Client{
		ID:              row.ClientID,
		Secret:          row.Secret,
		CreatedAt:       unixSecs(row.CreatedAt),
		ExpiresAt:       unixSecs(row.ExpiresAt),
		SecretExpiresAt: unixSecs(row.SecretExpiresAt),
		ClientMeta: goidc.ClientMeta{
			Name:                   row.Name,
			RedirectURIs:           row.RedirectURIs,
			GrantTypes:             grants,
			ResponseTypes:          responses,
			PostLogoutRedirectURIs: row.PostLogoutRedirectURIs,
			ScopeIDs:               row.Scopes,
			SubIdentifierType:      subject,
			TokenAuthnMethod:       goidc.AuthnMethod(row.TokenAuthnMethod),
		},
	}, nil
}

// unixSecs is the seconds count goidc stores for a timestamp. A zero time stays
// zero, because goidc omits the field then.
func unixSecs(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	return int(t.Unix())
}
