package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/luikyv/go-oidc/pkg/goidc"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNoSigningKey reports that a tenant has no active key for the requested
// algorithm. The provider build fails on it.
var ErrNoSigningKey = errors.New("no active signing key")

// KeyService serves the key set of one tenant: the public document for the
// JWKS endpoint, and the signer for new tokens.
type KeyService struct {
	repo   *KeyRepository
	cipher *aocrypto.Cipher
	log    logger.Logger
}

// NewKeyService takes the cipher that sealed oidc_keys.private_key. A nil
// cipher matches the development bootstrap, which stores the private half
// unsealed.
func NewKeyService(repo *KeyRepository, cipher *aocrypto.Cipher, log logger.Logger) *KeyService {
	return &KeyService{repo: repo, cipher: cipher, log: log}
}

// PublicKeySet returns the document the JWKS endpoint of one tenant serves.
func (s *KeyService) PublicKeySet(ctx context.Context, tenantID string) (goidc.JSONWebKeySet, error) {
	keys, err := s.repo.ListSigningKeys(ctx, tenantID)
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}
	return publicKeySet(keys)
}

// Signer returns the kid and the signer of the active key of one tenant. The
// shape matches goidc.SignerFunc, with the tenant bound by the caller.
func (s *KeyService) Signer(ctx context.Context, tenantID string, alg goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
	keys, err := s.repo.ListSigningKeys(ctx, tenantID)
	if err != nil {
		return "", nil, err
	}
	kid, signer, err := signingKey(keys, s.cipher, alg)
	if err != nil {
		s.log.Error("select signing key",
			logger.String("tenant_id", tenantID),
			logger.String("alg", string(alg)),
			logger.Err(err))
		return "", nil, err
	}
	return kid, signer, nil
}

// signingKey unseals the private half of the active key that carries alg. An
// inactive key never signs, so a tenant without an active key fails here.
func signingKey(keys []Key, cipher *aocrypto.Cipher, alg goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
	for _, key := range keys {
		if key.State != KeyStateActive || key.Algorithm != string(alg) {
			continue
		}
		privateJWK := key.PrivateKey
		if cipher != nil {
			plain, err := cipher.Decrypt(key.PrivateKey)
			if err != nil {
				return "", nil, fmt.Errorf("unseal private JWK of key %s: %w", key.ID, err)
			}
			privateJWK = plain
		}
		var jwk goidc.JSONWebKey
		if err := json.Unmarshal(privateJWK, &jwk); err != nil {
			return "", nil, fmt.Errorf("decode private JWK of key %s: %w", key.ID, err)
		}
		signer, ok := jwk.Key.(crypto.Signer)
		if !ok {
			return "", nil, fmt.Errorf("private JWK of key %s is a %T, which cannot sign", key.ID, jwk.Key)
		}
		return key.ID, joseSigner(signer), nil
	}
	return "", nil, fmt.Errorf("%w for algorithm %s", ErrNoSigningKey, alg)
}

// joseSigner adapts one private key to what the protocol engine needs. The
// engine hands the signer to go-jose and writes what it returns straight into
// the JWS.
//
// An RSA key already returns what JOSE holds. An EC key does not: crypto.Signer
// returns the ASN.1 form, and RFC 7518 section 3.4 fixes the JWS signature at
// the fixed-width r||s form. An unadapted EC key therefore signs a token that
// verifies nowhere.
func joseSigner(signer crypto.Signer) crypto.Signer {
	if key, ok := signer.(*ecdsa.PrivateKey); ok {
		return ecdsaSigner{key: key}
	}
	return signer
}

// ecdsaSigner signs with an EC key and answers in the form JOSE holds.
type ecdsaSigner struct {
	key *ecdsa.PrivateKey
}

func (s ecdsaSigner) Public() crypto.PublicKey { return s.key.Public() }

// Sign returns r and s, each padded to the octet length of the curve, as RFC
// 7518 section 3.4 fixes them.
func (s ecdsaSigner) Sign(random io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	r, sig, err := ecdsa.Sign(random, s.key, digest)
	if err != nil {
		return nil, fmt.Errorf("sign with EC key: %w", err)
	}

	size := (s.key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	sig.FillBytes(out[size:])
	return out, nil
}

// publicKeySet turns key rows into the document the JWKS endpoint serves. The
// row id becomes the kid, so a token header names the row that signed it.
func publicKeySet(keys []Key) (goidc.JSONWebKeySet, error) {
	set := goidc.JSONWebKeySet{Keys: make([]goidc.JSONWebKey, 0, len(keys))}
	for _, key := range keys {
		var jwk goidc.JSONWebKey
		if err := json.Unmarshal(key.PublicKey, &jwk); err != nil {
			return goidc.JSONWebKeySet{}, fmt.Errorf("decode public JWK of key %s: %w", key.ID, err)
		}
		jwk.KeyID = key.ID
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}
