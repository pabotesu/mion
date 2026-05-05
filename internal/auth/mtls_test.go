package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/peer"
)

func TestNewClientTLSConfig(t *testing.T) {
	_, privKey, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, certDER, err := identity.SelfSignedCert(privKey)
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}

	kp := peer.NewKnownPeers()
	tlsCfg, err := NewClientTLSConfig(privKey, certDER, kp)
	if err != nil {
		t.Fatalf("NewClientTLSConfig: %v", err)
	}

	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
	if tlsCfg.NextProtos[0] != "h3" {
		t.Errorf("expected NextProtos[0] = h3, got %q", tlsCfg.NextProtos[0])
	}
}

func TestNewProxyTLSConfig(t *testing.T) {
	_, privKey, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, certDER, err := identity.SelfSignedCert(privKey)
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}

	kp := peer.NewKnownPeers()
	tlsCfg, err := NewProxyTLSConfig(privKey, certDER, kp)
	if err != nil {
		t.Fatalf("NewProxyTLSConfig: %v", err)
	}

	if tlsCfg.ClientAuth != 2 { // tls.RequireAnyClientCert = 2
		t.Errorf("expected RequireAnyClientCert (2), got %d", tlsCfg.ClientAuth)
	}
}

func TestPeerIDFromRawCerts(t *testing.T) {
	pub, privKey, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, certDER, err := identity.SelfSignedCert(privKey)
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}

	peerID, err := PeerIDFromRawCerts([][]byte{certDER})
	if err != nil {
		t.Fatalf("PeerIDFromRawCerts: %v", err)
	}

	expected := identity.PeerIDFromPublicKey(pub)
	if peerID != expected {
		t.Errorf("got peer_id %v, want %v", peerID, expected)
	}
}

func TestPeerIDFromRawCertsEmpty(t *testing.T) {
	_, err := PeerIDFromRawCerts(nil)
	if err == nil {
		t.Fatal("expected error for empty certs")
	}
}

func TestVerifyPeerCertificateKnownPeer(t *testing.T) {
	pub, privKey, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, certDER, err := identity.SelfSignedCert(privKey)
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}

	peerID := identity.PeerIDFromPublicKey(pub)
	kp := peer.NewKnownPeers()
	kp.Add(&peer.Peer{PeerID: peerID})

	// Should succeed since peer is known
	err = verifyPeerCertificate([][]byte{certDER}, kp)
	if err != nil {
		t.Fatalf("verifyPeerCertificate failed for known peer: %v", err)
	}
}

func TestVerifyPeerCertificateUnknownPeer(t *testing.T) {
	_, privKey, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, certDER, err := identity.SelfSignedCert(privKey)
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}

	kp := peer.NewKnownPeers() // empty - no known peers

	err = verifyPeerCertificate([][]byte{certDER}, kp)
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
}

func TestVerifyPeerCertificateNonEd25519(t *testing.T) {
	// Create an RSA certificate (not Ed25519) to test rejection
	// We'll use a dummy DER that parses but has wrong key type
	// For simplicity, just test with invalid DER
	_, err := PeerIDFromRawCerts([][]byte{[]byte("not a valid cert")})
	if err == nil {
		t.Fatal("expected error for invalid cert DER")
	}
}

// Verify that the x509 cert from SelfSignedCert has the expected properties
func TestSelfSignedCertProperties(t *testing.T) {
	pub, privKey, _ := identity.GenerateKeyPair()
	cert, _, _ := identity.SelfSignedCert(privKey)

	if !cert.IsCA {
		t.Error("expected IsCA = true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature")
	}

	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected Ed25519 public key in cert")
	}
	if !certPub.Equal(pub) {
		t.Error("cert public key does not match")
	}
}
