package openvpn

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/youmark/pkcs8"
)

// Errors a caller can tell apart: the key needs a password it was not given, or the one given is wrong.
// Both messages say "key password", which the macOS app matches to ask for it again.
var (
	ErrKeyPasswordNeeded = errors.New("the private key needs its key password")
	ErrKeyPasswordWrong  = errors.New("the key password is wrong")
)

// DecryptKey returns the PEM of a passphrase-protected private key without the protection. The engine takes the
// key as plain PEM (sing-box has no password option), so the password is used here once and the plain key lives
// only in the engine's in-memory options. Two forms are read: PKCS#8 "ENCRYPTED PRIVATE KEY" (what OpenSSL 1.1+
// writes: PBKDF2 with AES or 3DES) and the older "Proc-Type: 4,ENCRYPTED" PEM (AES or 3DES in CBC mode).
func DecryptKey(keyPEM, password string) (string, error) {
	if password == "" {
		return "", ErrKeyPasswordNeeded
	}
	block, _ := pem.Decode([]byte(strings.TrimSpace(keyPEM)))
	if block == nil {
		return "", fmt.Errorf("the private key is not valid PEM")
	}
	switch {
	case block.Type == "ENCRYPTED PRIVATE KEY":
		key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
		if err != nil {
			// The library does not separate a wrong password from an unsupported cipher; say both.
			return "", fmt.Errorf("%w (or the key uses an encryption this app can't read: %v)", ErrKeyPasswordWrong, err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("private key: %w", err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
	case x509.IsEncryptedPEMBlock(block): //nolint:staticcheck // the only reader for OpenSSL's legacy encrypted PEM; the format is what the profile has
		der, err := x509.DecryptPEMBlock(block, []byte(password)) //nolint:staticcheck
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				return "", ErrKeyPasswordWrong
			}
			return "", fmt.Errorf("private key: %w", err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})), nil
	}
	return "", fmt.Errorf("the private key is marked encrypted but is in a form this app can't read (%s)", block.Type)
}
