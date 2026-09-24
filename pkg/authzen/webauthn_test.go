package authzen_test

import (
	"testing"

	"github.com/jralmaraz/authzen-poc/pkg/authzen"
)

func TestRegisterPasskeyCreatesCredential(t *testing.T) {
	cred, err := authzen.RegisterPasskey("alice@example.com")
	if err != nil {
		t.Fatalf("RegisterPasskey: %v", err)
	}
	if cred.ID == "" {
		t.Error("credential ID is empty")
	}
	if cred.PublicKey == nil {
		t.Error("public key is nil")
	}
	if cred.UserID != "alice@example.com" {
		t.Errorf("UserID: got %q", cred.UserID)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	cred, err := authzen.RegisterPasskey("alice@example.com")
	if err != nil {
		t.Fatalf("RegisterPasskey: %v", err)
	}
	challenge := []byte("server-generated-challenge-12345")
	assertion, err := cred.Sign(challenge)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if assertion == "" {
		t.Fatal("empty assertion")
	}
	if err := authzen.VerifyPasskeyAssertion(cred, challenge, assertion); err != nil {
		t.Errorf("VerifyPasskeyAssertion: %v", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	alice, err := authzen.RegisterPasskey("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := authzen.RegisterPasskey("bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("challenge")
	assertion, err := alice.Sign(challenge)
	if err != nil {
		t.Fatal(err)
	}
	// Verify alice's assertion with bob's credential — must fail.
	if err := authzen.VerifyPasskeyAssertion(bob, challenge, assertion); err == nil {
		t.Error("expected error for wrong key, got nil")
	}
}

func TestVerifyTamperedChallenge(t *testing.T) {
	cred, err := authzen.RegisterPasskey("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("original-challenge")
	assertion, err := cred.Sign(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := authzen.VerifyPasskeyAssertion(cred, []byte("tampered-challenge"), assertion); err == nil {
		t.Error("expected error for tampered challenge, got nil")
	}
}

func TestPasskeySubjectHasCorrectType(t *testing.T) {
	cred, err := authzen.RegisterPasskey("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	sub := authzen.PasskeySubject(cred)
	if sub.Type != "webauthn" {
		t.Errorf("Subject.Type: got %q, want %q", sub.Type, "webauthn")
	}
	if sub.ID != cred.ID {
		t.Errorf("Subject.ID: got %q, want %q", sub.ID, cred.ID)
	}
}

func TestTrustTierOrdering(t *testing.T) {
	tiers := map[string]int{
		"spiffe":      authzen.TrustTier("spiffe"),
		"workload":    authzen.TrustTier("workload"),
		"webauthn":    authzen.TrustTier("webauthn"),
		"user":        authzen.TrustTier("user"),
		"oauth_token": authzen.TrustTier("oauth_token"),
		"api_key":     authzen.TrustTier("api_key"),
		"anonymous":   authzen.TrustTier("anonymous"),
	}

	checks := []struct{ a, b string }{
		{"spiffe", "webauthn"},
		{"webauthn", "user"},
		{"user", "api_key"},
		{"api_key", "anonymous"},
	}
	for _, c := range checks {
		if tiers[c.a] <= tiers[c.b] {
			t.Errorf("expected TrustTier(%q)=%d > TrustTier(%q)=%d",
				c.a, tiers[c.a], c.b, tiers[c.b])
		}
	}
	if tiers["spiffe"] != tiers["workload"] {
		t.Errorf("spiffe and workload should have same tier")
	}
}

func TestPRFOutputDeterministic(t *testing.T) {
	cred, err := authzen.RegisterPasskey("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("session-binding-key")
	out1 := cred.PRFOutput(input)
	out2 := cred.PRFOutput(input)
	if string(out1) != string(out2) {
		t.Error("PRFOutput not deterministic for same credential and input")
	}
	if len(out1) != 32 {
		t.Errorf("PRFOutput length: got %d, want 32", len(out1))
	}
}
