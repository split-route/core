package openvpn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
)

// The keys are made here, in both forms OpenSSL writes, so no secret sits in testdata.
func encryptedKeys(t *testing.T, password string) map[string]struct{ enc, plain string } {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]struct{ enc, plain string }{}
	for name, k := range map[string]any{"rsa": rsaKey, "ec": ecKey} {
		plainDER, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		plain := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plainDER}))
		encDER, err := pkcs8.MarshalPrivateKey(k, []byte(password), nil)
		if err != nil {
			t.Fatal(err)
		}
		out["pkcs8 "+name] = struct{ enc, plain string }{string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})), plain}
	}
	// The older form: the key's own DER, encrypted by the PEM layer.
	rsaDER := x509.MarshalPKCS1PrivateKey(rsaKey)
	for _, alg := range []x509.PEMCipher{x509.PEMCipherAES128, x509.PEMCipherAES256, x509.PEMCipher3DES} {
		b, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", rsaDER, []byte(password), alg) //nolint:staticcheck
		if err != nil {
			t.Fatal(err)
		}
		out["legacy "+string(rune('0'+alg))] = struct{ enc, plain string }{string(pem.EncodeToMemory(b)), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaDER}))}
	}
	return out
}

func TestDecryptKey(t *testing.T) {
	const pw = "correct horse"
	for name, k := range encryptedKeys(t, pw) {
		t.Run(name, func(t *testing.T) {
			got, err := DecryptKey(k.enc, pw)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(got, "ENCRYPTED") {
				t.Fatalf("still encrypted:\n%s", got)
			}
			// The same key: parse both and compare their public halves.
			if pub(t, got) != pub(t, k.plain) {
				t.Error("a different key came out")
			}
			if _, err := DecryptKey(k.enc, "wrong"); !errors.Is(err, ErrKeyPasswordWrong) {
				t.Errorf("wrong password: err = %v", err)
			}
			if _, err := DecryptKey(k.enc, ""); !errors.Is(err, ErrKeyPasswordNeeded) {
				t.Errorf("no password: err = %v", err)
			}
		})
	}
}

func pub(t *testing.T, keyPEM string) string {
	t.Helper()
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil {
		t.Fatal("not PEM")
	}
	var k any
	var err error
	if b.Type == "RSA PRIVATE KEY" {
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	} else {
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	}
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(k.(interface{ Public() crypto.PublicKey }).Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(der)
}

// An encrypted key in a profile converts once the password is given, and the plain key is what the engine gets.
func TestEndpointDecryptsTheClientKey(t *testing.T) {
	k := encryptedKeys(t, "pw")["pkcs8 ec"]
	text := strings.Replace(aliLike, keyBlockOf(t, aliLike), k.enc, 1)
	p, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if !p.KeyEncrypted {
		t.Fatal("the profile's key was not seen as encrypted")
	}
	if _, err := Endpoint(p, "x", "u", "p", ""); !errors.Is(err, ErrKeyPasswordNeeded) {
		t.Errorf("no key password: err = %v", err)
	}
	if _, err := Endpoint(p, "x", "u", "p", "nope"); !errors.Is(err, ErrKeyPasswordWrong) {
		t.Errorf("wrong key password: err = %v", err)
	}
	ep, err := Endpoint(p, "x", "u", "p", "pw")
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Join(ep["tls"].(map[string]any)["client_key"].([]string), "\n")
	if !strings.HasPrefix(key, "-----BEGIN PRIVATE KEY-----") || strings.Contains(key, "ENCRYPTED") {
		t.Errorf("client_key = %q", key)
	}
}

func keyBlockOf(t *testing.T, profile string) string {
	t.Helper()
	i := strings.Index(profile, "<key>\n")
	j := strings.Index(profile, "</key>")
	if i < 0 || j < 0 {
		t.Fatal("no <key> block in the fixture")
	}
	return profile[i+len("<key>\n") : j]
}
