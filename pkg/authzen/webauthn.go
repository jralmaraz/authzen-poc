package authzen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// PasskeyCredential simulates a WebAuthn Level 4 device-bound passkey (ES256 / P-256).
// In a real implementation the private key never leaves the authenticator hardware;
// here it lives in memory for PoC purposes.
type PasskeyCredential struct {
	ID        string           // base64url-encoded 16-byte credential identifier
	PublicKey *ecdsa.PublicKey // verification key
	UserID    string
	prfSecret []byte           // PRF extension seed (WebAuthn L4 §10.1.4)
	priv      *ecdsa.PrivateKey
}

// RegisterPasskey generates a new simulated passkey credential for userID.
func RegisterPasskey(userID string) (*PasskeyCredential, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate credential id: %w", err)
	}
	prf := make([]byte, 32)
	if _, err := rand.Read(prf); err != nil {
		return nil, fmt.Errorf("generate prf seed: %w", err)
	}
	return &PasskeyCredential{
		ID:        base64.RawURLEncoding.EncodeToString(idBytes),
		PublicKey: &priv.PublicKey,
		UserID:    userID,
		prfSecret: prf,
		priv:      priv,
	}, nil
}

// Sign produces a base64url-encoded ES256 raw signature (r‖s, 64 bytes) over challenge.
func (c *PasskeyCredential) Sign(challenge []byte) (string, error) {
	digest := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, c.priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(passkeyRawSig(r, s)), nil
}

// PRFOutput returns HMAC-SHA256(prfSecret, input), simulating the WebAuthn L4 PRF extension.
// A real authenticator derives this from its secret seed; here we use an in-memory seed.
func (c *PasskeyCredential) PRFOutput(input []byte) []byte {
	mac := hmac.New(sha256.New, c.prfSecret)
	mac.Write(input)
	return mac.Sum(nil)
}

// VerifyPasskeyAssertion verifies a base64url ES256 raw assertion against cred's public key.
func VerifyPasskeyAssertion(cred *PasskeyCredential, challenge []byte, assertionB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(assertionB64)
	if err != nil {
		return fmt.Errorf("decode assertion: %w", err)
	}
	if len(sig) != 64 {
		return errors.New("invalid raw signature length: expected 64 bytes")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(challenge)
	if !ecdsa.Verify(cred.PublicKey, digest[:], r, s) {
		return errors.New("assertion signature invalid")
	}
	return nil
}

// PasskeySubject returns an AuthZEN Subject with type "webauthn" and the credential ID.
func PasskeySubject(cred *PasskeyCredential) Subject {
	return Subject{Type: "webauthn", ID: cred.ID}
}

// TrustTier returns a numeric trust level for a subject type (higher = stronger auth).
//
//	spiffe/workload: 5 — cryptographic workload identity (mTLS / SPIFFE)
//	webauthn:        4 — hardware-bound passkey, phishing-resistant
//	user/oidc:       3 — OIDC-authenticated user (password or SSO)
//	api_key:         2 — shared secret, no user binding
//	anonymous:       0 — unauthenticated caller
func TrustTier(subjectType string) int {
	switch subjectType {
	case "spiffe", "workload":
		return 5
	case "webauthn":
		return 4
	case "user", "oidc", "oauth_token":
		return 3
	case "api_key":
		return 2
	default:
		return 0
	}
}

func passkeyRawSig(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):64], sb)
	return out
}
