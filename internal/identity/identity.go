// Package identity provides Ed25519 key management, PeerID derivation,
// and self-signed certificate generation for mTLS.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

// PeerID is a SHA-256 hash of the Ed25519 public key.
// This is the canonical identifier for a peer in MION.
type PeerID [sha256.Size]byte

// String returns the base64-encoded representation of the PeerID.
func (id PeerID) String() string {
	return base64.StdEncoding.EncodeToString(id[:])
}

// PeerIDFromPublicKey derives a PeerID from an Ed25519 public key.
func PeerIDFromPublicKey(pub ed25519.PublicKey) PeerID {
	return sha256.Sum256(pub)
}

// PeerIDFromBase64 parses a base64-encoded PeerID string.
func PeerIDFromBase64(s string) (PeerID, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return PeerID{}, fmt.Errorf("identity: invalid base64: %w", err)
	}
	if len(b) != sha256.Size {
		return PeerID{}, fmt.Errorf("identity: invalid peer_id length: %d", len(b))
	}
	var id PeerID
	copy(id[:], b)
	return id, nil
}

// GenerateKeyPair generates a new Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: failed to generate key pair: %w", err)
	}
	return pub, priv, nil
}

// SelfSignedCert generates a self-signed X.509 certificate embedding the
// Ed25519 public key. Used for mTLS where peer_id verification happens
// in VerifyPeerCertificate, not via CA chain.
func SelfSignedCert(priv ed25519.PrivateKey) (*x509.Certificate, []byte, error) {
	pub := priv.Public().(ed25519.PublicKey)
	peerID := PeerIDFromPublicKey(pub)

	// Random serial number (required by X.509)
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: failed to generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: peerID.String(),
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour), // ~10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // Required for self-signed cert verification
	}

	// Self-sign: issuer = subject, signed with our own private key
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: failed to create certificate: %w", err)
	}

	// Parse back to get the structured certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: failed to parse certificate: %w", err)
	}

	return cert, certDER, nil
}
