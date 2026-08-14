package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Self-describing ciphertext (harden-core F-5, ticket 16).
//
// Stored ciphertext used to be a bare nonce||ct||tag with nothing saying which
// key sealed it. That single omission is what made root-key rotation
// impossible: rotating meant an offline stop-the-world re-encrypt of every
// sealed column with both keys in hand, because nothing could tell an old blob
// from a new one.
//
// A sealed blob now carries a header ahead of the payload:
//
//	"AOK1" | keyIDLen (1 byte) | keyID | nonce || ciphertext || tag
//
// Decryption dispatches on keyID; encryption always uses the current key. Two
// keys coexist, which is the precondition for every other F-5 ticket.
//
// LEGACY. A blob that does not start with the magic is pre-header ciphertext
// and is opened with the current environment-derived key — the key that
// necessarily sealed it, since there was only ever one. This is what makes the
// finding shippable with no data migration and no downtime. A legacy blob's
// first four bytes are the first four of a random nonce, so the chance one
// starts with "AOK1" is 2^-32; a false positive there fails GCM
// authentication and surfaces as a decrypt error rather than as silent
// corruption.
const (
	sealMagic   = "AOK1"
	maxKeyIDLen = 255
)

// keyIDFor derives the identifier stored in the header from the DERIVED AES key,
// not from the configured secret. It is a one-way 4-byte tag: long enough that
// two live keys colliding is not a practical concern, and it reveals nothing
// about the key it names beyond "this is a different one".
func keyIDFor(aesKey []byte) string {
	sum := sha256.Sum256(append([]byte("ao:db-encryption:key-id:v1\x00"), aesKey...))
	return hex.EncodeToString(sum[:4])
}

// aeadFor derives the AES-256-GCM AEAD for a configured key string, plus the id
// that names it. It is the single derivation path: NewCipher and every prior
// key added to the ring go through it, so a key cannot end up with one id in
// one place and another elsewhere.
func aeadFor(key string) (cipher.AEAD, string, error) {
	if key == "" {
		return nil, "", errors.New("crypto: encryption key is empty")
	}
	sum := sha256.Sum256(append([]byte(encKeyDomain), key...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, "", fmt.Errorf("crypto: new aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("crypto: new gcm: %w", err)
	}
	return aead, keyIDFor(sum[:]), nil
}

// header prefixes payload with the magic and this cipher's key id.
func (c *Cipher) header() []byte {
	h := make([]byte, 0, len(sealMagic)+1+len(c.keyID))
	h = append(h, sealMagic...)
	h = append(h, byte(len(c.keyID)))
	return append(h, c.keyID...)
}

// splitSealed separates a stored blob into its key id and payload. A blob with
// no header returns ("", data, false) — the legacy shape.
func splitSealed(data []byte) (keyID string, payload []byte, hasHeader bool) {
	prefix := len(sealMagic)
	if len(data) < prefix+1 || string(data[:prefix]) != sealMagic {
		return "", data, false
	}
	idLen := int(data[prefix])
	if idLen == 0 || len(data) < prefix+1+idLen {
		// Well-formed magic with a truncated header: not a legacy blob, and not
		// openable either. Report it as headerless so Decrypt fails on
		// authentication rather than silently reading past the buffer.
		return "", data, false
	}
	start := prefix + 1
	return string(data[start : start+idLen]), data[start+idLen:], true
}

// AddPriorKey teaches the cipher to open blobs sealed under an earlier key
// WITHOUT making it the sealing key. This is the read half of a root-key
// rotation: during a rotation run both keys must open, only the new one seals.
// Re-adding the current key is a no-op.
func (c *Cipher) AddPriorKey(key string) error {
	aead, id, err := aeadFor(key)
	if err != nil {
		return err
	}
	if id == c.keyID {
		return nil
	}
	if len(id) > maxKeyIDLen {
		return fmt.Errorf("crypto: key id %q is too long for the header", id)
	}
	if c.prior == nil {
		c.prior = make(map[string]cipher.AEAD, 1)
	}
	c.prior[id] = aead
	return nil
}

// KeyID returns the identifier of the key this cipher seals with. Callers use
// it to tell whether a stored blob is already under the current key — which is
// what makes an interrupted re-encrypt resumable rather than restartable.
func (c *Cipher) KeyID() string { return c.keyID }

// SealedUnderCurrentKey reports whether data is already sealed under this
// cipher's key. Legacy headerless data is never "current": it has to be
// re-sealed to become identifiable.
func (c *Cipher) SealedUnderCurrentKey(data []byte) bool {
	id, _, ok := splitSealed(data)
	return ok && id == c.keyID
}

// aeadForBlob picks the AEAD that can open data. A headerless blob predates the
// header and was necessarily sealed with the environment key the cipher was
// built from, so it goes to the current AEAD.
func (c *Cipher) aeadForBlob(data []byte) (cipher.AEAD, []byte, error) {
	id, payload, hasHeader := splitSealed(data)
	if !hasHeader || id == c.keyID {
		return c.aead, payload, nil
	}
	if aead, ok := c.prior[id]; ok {
		return aead, payload, nil
	}
	return nil, nil, fmt.Errorf("crypto: no key %q available to decrypt", id)
}
