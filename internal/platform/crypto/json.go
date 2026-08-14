package crypto

import (
	"encoding/json"
	"fmt"
)

// SealJSON JSON-encodes v and, when cipher is non-nil, encrypts the result. A nil
// cipher yields the plaintext JSON (dev-only, unencrypted at rest). This is the
// shared blob discipline for the login-session and OIDC storage services.
func SealJSON(cipher *Cipher, v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	if cipher == nil {
		return data, nil
	}
	return cipher.Encrypt(data)
}

// OpenJSON reverses SealJSON: decrypt (when cipher is non-nil) then JSON-decode
// the result into v.
func OpenJSON(cipher *Cipher, blob []byte, v any) error {
	data := blob
	if cipher != nil {
		var err error
		if data, err = cipher.Decrypt(blob); err != nil {
			return err
		}
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}
