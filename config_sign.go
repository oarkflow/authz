package authz

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const ConfigSignaturePrefix = "# authz-signature:ed25519:"

func GenerateConfigSigningKey() (publicKey, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

func SignConfig(data []byte, privateKeyB64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", err
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid ed25519 private key size")
	}
	canonical := canonicalConfigBytes(data)
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), canonical)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func VerifyConfigSignature(data []byte, publicKeyB64 string) error {
	pubBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return err
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key size")
	}
	signature, ok := ExtractConfigSignature(data)
	if !ok {
		return fmt.Errorf("config signature not found")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonicalConfigBytes(data), sigBytes) {
		return fmt.Errorf("config signature verification failed")
	}
	return nil
}

func SignConfigFile(filename, privateKeyB64 string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return SignConfig(data, privateKeyB64)
}

func ExtractConfigSignature(data []byte) (string, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ConfigSignaturePrefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, ConfigSignaturePrefix)), true
		}
	}
	return "", false
}

func AppendConfigSignature(data []byte, signature string) []byte {
	canonical := stripConfigSignature(data)
	if len(canonical) > 0 && canonical[len(canonical)-1] != '\n' {
		canonical = append(canonical, '\n')
	}
	canonical = append(canonical, []byte(ConfigSignaturePrefix+signature+"\n")...)
	return canonical
}

func canonicalConfigBytes(data []byte) []byte {
	return []byte(strings.TrimRight(string(stripConfigSignature(data)), "\n"))
}

func stripConfigSignature(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), ConfigSignaturePrefix) {
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}
