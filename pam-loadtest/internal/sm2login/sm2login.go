// Package sm2login implements SM2 password encryption used by newer
// SGP-PAM builds for the /login endpoint.
package sm2login

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/tjfoc/gmsm/sm2"
)

// EncryptPassword encrypts password with the SM2 public key returned by the
// PAM /login/crypto-key endpoint. cipherMode is the mode string from the
// endpoint ("C1C3C2" or "C1C2C3"); an empty value defaults to C1C3C2.
// It returns the hex ciphertext expected by POST /login as
// encryptedPassword.
func EncryptPassword(password, publicKeyHex, cipherMode string) (string, error) {
	keyHex := strings.TrimSpace(publicKeyHex)
	keyHex = strings.TrimPrefix(keyHex, "04")
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("sm2 login: invalid public key hex: %w", err)
	}
	if len(raw) != 64 {
		return "", fmt.Errorf("sm2 login: public key length %d, want 64 bytes", len(raw))
	}
	curve := sm2.P256Sm2()
	pub := &sm2.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(raw[:32]),
		Y:     new(big.Int).SetBytes(raw[32:]),
	}
	mode := sm2.C1C3C2
	if strings.EqualFold(cipherMode, "C1C2C3") {
		mode = sm2.C1C2C3
	}
	cipher, err := sm2.Encrypt(pub, []byte(password), rand.Reader, mode)
	if err != nil {
		return "", fmt.Errorf("sm2 login: encrypt: %w", err)
	}
	// The tjfoc Encrypt output begins with the 0x04 uncompressed point
	// marker; SGP-PAM expects the raw C1C3C2 stream (64-byte C1) without it.
	if len(cipher) > 1 && cipher[0] == 0x04 {
		cipher = cipher[1:]
	}
	return hex.EncodeToString(cipher), nil
}
