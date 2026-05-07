package authz

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

const ConfigSignaturePrefix = "# authz-signature:ed25519:"

var configSignaturePrefixBytes = []byte(ConfigSignaturePrefix)

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
	return VerifyConfigSignatureWithKey(data, ed25519.PublicKey(pubBytes))
}

func VerifyConfigSignatureWithKey(data []byte, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key size")
	}
	signature, ok := extractConfigSignatureBytes(data)
	if !ok {
		return fmt.Errorf("config signature not found")
	}
	var sig [ed25519.SignatureSize]byte
	n, err := base64.StdEncoding.Decode(sig[:], signature)
	if err != nil {
		return err
	}
	if n != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature size")
	}
	if !ed25519.Verify(publicKey, canonicalConfigBytes(data), sig[:]) {
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
	signature, ok := extractConfigSignatureBytes(data)
	if !ok {
		return "", false
	}
	return string(signature), true
}

func extractConfigSignatureBytes(data []byte) ([]byte, bool) {
	for start := 0; start <= len(data); {
		end := start
		for end < len(data) && data[end] != '\n' {
			end++
		}
		line := bytes.TrimSpace(data[start:end])
		if bytes.HasPrefix(line, configSignaturePrefixBytes) {
			return bytes.TrimSpace(line[len(configSignaturePrefixBytes):]), true
		}
		if end == len(data) {
			break
		}
		start = end + 1
	}
	return nil, false
}

func AppendConfigSignature(data []byte, signature string) []byte {
	canonical := stripConfigSignature(data)
	out := make([]byte, 0, len(canonical)+1+len(ConfigSignaturePrefix)+len(signature)+1)
	out = append(out, canonical...)
	if len(canonical) > 0 && canonical[len(canonical)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, ConfigSignaturePrefix...)
	out = append(out, signature...)
	out = append(out, '\n')
	return out
}

func canonicalConfigBytes(data []byte) []byte {
	return bytes.TrimRight(stripConfigSignature(data), "\n")
}

func stripConfigSignature(data []byte) []byte {
	var out []byte
	last := 0
	for start := 0; start <= len(data); {
		end := start
		for end < len(data) && data[end] != '\n' {
			end++
		}
		lineEnd := end
		endWithNewline := end
		if endWithNewline < len(data) {
			endWithNewline++
		}
		line := bytes.TrimSpace(data[start:lineEnd])
		if bytes.HasPrefix(line, configSignaturePrefixBytes) {
			if out == nil {
				if endWithNewline == len(data) {
					return data[:start]
				}
				out = make([]byte, 0, len(data)-(endWithNewline-start))
			}
			out = append(out, data[last:start]...)
			last = endWithNewline
		}
		if end == len(data) {
			break
		}
		start = end + 1
	}
	if out == nil {
		return data
	}
	return append(out, data[last:]...)
}
