package identity_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/pabotesu/mion/internal/identity"
)

func TestPeerIDFromPublicKey(t *testing.T) {
	pub, _, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	id1 := identity.PeerIDFromPublicKey(pub)
	id2 := identity.PeerIDFromPublicKey(pub)
	if id1 != id2 {
		t.Fatal("same public key should produce same PeerID")
	}

	pub2, _, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	id3 := identity.PeerIDFromPublicKey(pub2)
	if id1 == id3 {
		t.Fatal("different public keys should produce different PeerIDs")
	}
}

func TestPeerIDBase64Roundtrip(t *testing.T) {
	pub, _, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	id := identity.PeerIDFromPublicKey(pub)
	s := id.String()

	parsed, err := identity.PeerIDFromBase64(s)
	if err != nil {
		t.Fatalf("failed to parse base64 PeerID: %v", err)
	}
	if id != parsed {
		t.Fatal("PeerID roundtrip failed")
	}
}

func TestPeerIDFromBase64Invalid(t *testing.T) {
	_, err := identity.PeerIDFromBase64("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}

	_, err = identity.PeerIDFromBase64("AAAA")
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestSelfSignedCert(t *testing.T) {
	_, priv, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	cert, certDER, err := identity.SelfSignedCert(priv)
	if err != nil {
		t.Fatalf("SelfSignedCert failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("certDER is empty")
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}

	// Subject CN should be the PeerID
	pub := priv.Public().(ed25519.PublicKey)
	expectedCN := identity.PeerIDFromPublicKey(pub).String()
	if cert.Subject.CommonName != expectedCN {
		t.Fatalf("expected CN=%s, got CN=%s", expectedCN, cert.Subject.CommonName)
	}

	// Public key should be Ed25519
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("certificate public key is not Ed25519")
	}
	if !certPub.Equal(pub) {
		t.Fatal("certificate public key does not match")
	}

	// Key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("missing KeyUsageDigitalSignature")
	}

	// ExtKeyUsage
	hasClient, hasServer := false, false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
		if usage == x509.ExtKeyUsageServerAuth {
			hasServer = true
		}
	}
	if !hasClient {
		t.Fatal("missing ExtKeyUsageClientAuth")
	}
	if !hasServer {
		t.Fatal("missing ExtKeyUsageServerAuth")
	}

	// Self-signed: verify signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("certificate is not properly self-signed: %v", err)
	}
}
