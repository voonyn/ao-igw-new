package oidc_test

// A software authenticator that lives in this test process.
//
// A Passkey ceremony needs a device. This one holds an in-memory key pair,
// builds the same bytes a real device builds, and answers what
// navigator.credentials.create() would hand the page. It exists so the flow test
// can drive the gateway over HTTP against the real library, with no interface
// and no fake in the production code.
//
// It is a registration device today. Ticket 07 signs an assertion with the same
// key pair, which is why the key is kept.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The authenticator data flags this device reports: the person was present, the
// person was verified, and attested credential data follows.
//
// Specification: §6.1. Authenticator Data.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttestedData = 0x40
)

// coordinateBytes is the length of one P-256 coordinate. A short one is
// left-padded, because a COSE key names a fixed width and not a number.
const coordinateBytes = 32

// authenticator is one software device: a key pair, the credential id it minted
// for it, and the signature counter it reports.
//
// The counter stays zero. A synced passkey reports zero too, which is why the
// gateway logs a counter regression instead of refusing the assertion.
type authenticator struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

// newAuthenticator mints one device. Each test that needs two devices calls it
// twice, so the two hold different key pairs and different credential ids.
func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the authenticator key: %v", err)
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("mint the credential id: %v", err)
	}
	return &authenticator{key: key, id: id}
}

// credentialID is the base64url spelling the browser and the gateway both use.
func (a *authenticator) credentialID() string {
	return base64.RawURLEncoding.EncodeToString(a.id)
}

// register answers what navigator.credentials.create() hands the page for one
// set of registration options.
//
// The challenge arrives base64url-encoded, exactly as the gateway answered it,
// and it is copied into the client data untouched. That copy is what the gateway
// compares against the challenge it stored.
//
// Attestation is "none", so the statement is empty and no signature is made
// here. A registration proves possession of the key pair through the public key
// it publishes, and the assertion later proves it with a signature.
func (a *authenticator) register(t *testing.T, rpID, origin, challenge string) json.RawMessage {
	t.Helper()

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encode the client data: %v", err)
	}

	object, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(t, rpID),
	})
	if err != nil {
		t.Fatalf("encode the attestation object: %v", err)
	}

	answer, err := json.Marshal(map[string]any{
		"id":    a.credentialID(),
		"rawId": a.credentialID(),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(object),
		},
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		t.Fatalf("encode the registration answer: %v", err)
	}
	return answer
}

// authData builds the authenticator data of one registration: the RP ID hash,
// the flags, the counter, and the attested credential data behind them.
//
// Specification: §6.1. Authenticator Data, and §6.5.2. Attested Credential Data.
func (a *authenticator) authData(t *testing.T, rpID string) []byte {
	t.Helper()

	hash := sha256.Sum256([]byte(rpID))

	var buf bytes.Buffer
	buf.Write(hash[:])
	buf.WriteByte(flagUserPresent | flagUserVerified | flagAttestedData)
	_ = binary.Write(&buf, binary.BigEndian, a.count)

	// The AAGUID names the make and model of the device. This one names nothing,
	// which is what a device that gives no attestation reports.
	buf.Write(make([]byte, 16))

	_ = binary.Write(&buf, binary.BigEndian, uint16(len(a.id)))
	buf.Write(a.id)
	buf.Write(a.publicKey(t))
	return buf.Bytes()
}

// publicKey is the public half of the key pair, in the COSE encoding a device
// publishes: an EC2 key on the P-256 curve, signing with ES256.
//
// Specification: RFC 8152 §13.1.1. Double Coordinate Curves.
func (a *authenticator) publicKey(t *testing.T) []byte {
	t.Helper()

	key := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: coordinate(a.key.PublicKey.X),
		-3: coordinate(a.key.PublicKey.Y),
	}

	encoded, err := cbor.Marshal(key)
	if err != nil {
		t.Fatalf("encode the cose public key: %v", err)
	}
	return encoded
}

// coordinate spells one curve coordinate at its fixed width. A coordinate that
// starts with a zero byte is shorter as a number, and a COSE key names a width.
func coordinate(value *big.Int) []byte {
	raw := value.Bytes()
	if len(raw) >= coordinateBytes {
		return raw
	}

	padded := make([]byte, coordinateBytes)
	copy(padded[coordinateBytes-len(raw):], raw)
	return padded
}

// tamper returns one registration answer with its client data replaced, so the
// challenge inside no longer matches the one the gateway stored.
//
// It is how the test proves that a wrong answer is refused. Nothing else about
// the answer changes, so the refusal is about the challenge and not about the
// shape of the body.
func tamper(t *testing.T, answer json.RawMessage) json.RawMessage {
	t.Helper()

	var whole map[string]any
	if err := json.Unmarshal(answer, &whole); err != nil {
		t.Fatalf("read the registration answer: %v", err)
	}

	response, ok := whole["response"].(map[string]any)
	if !ok {
		t.Fatalf("the registration answer holds no response: %s", answer)
	}

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   base64.RawURLEncoding.EncodeToString([]byte("not-the-challenge")),
		"origin":      "https://example.test",
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encode the client data: %v", err)
	}
	response["clientDataJSON"] = base64.RawURLEncoding.EncodeToString(clientData)

	changed, err := json.Marshal(whole)
	if err != nil {
		t.Fatalf("encode the changed answer: %v", err)
	}
	return changed
}

// registrationOptions is the half of the ceremony options this test reads.
//
// The portal passes the whole object to the browser and reads no field out of
// it. The test reads these three, because they are what the assertions below are
// about: the RP ID the credential binds to, the challenge the device answers,
// and the devices the person already holds.
type registrationOptions struct {
	PublicKey struct {
		Challenge    string `json:"challenge"`
		RelyingParty struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

// String names the options in a failure message.
func (o registrationOptions) String() string {
	return fmt.Sprintf("rp %s, %d excluded", o.PublicKey.RelyingParty.ID, len(o.PublicKey.ExcludeCredentials))
}
