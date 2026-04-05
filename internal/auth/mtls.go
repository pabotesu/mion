// Package auth provides mTLS configuration for MION.
// Both Client and Proxy use mTLS for hop-by-hop authentication.
// Peer verification is done by extracting the public key from the peer's
// certificate and checking it against KnownPeers, not via CA chain.
package auth

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/peer"
)

// PeerIDFromRawCerts extracts the Ed25519 public key from raw DER certificates
// and derives the PeerID. Used by the proxy handler to identify connected clients.
func PeerIDFromRawCerts(rawCerts [][]byte) (identity.PeerID, error) {
	if len(rawCerts) == 0 {
		return identity.PeerID{}, fmt.Errorf("auth: no certificate presented")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return identity.PeerID{}, fmt.Errorf("auth: failed to parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return identity.PeerID{}, fmt.Errorf("auth: certificate key is not Ed25519")
	}
	return identity.PeerIDFromPublicKey(pub), nil
}

// NewClientTLSConfig creates a tls.Config for the Client side.
// It presents our certificate and verifies the Proxy's peer_id via VerifyPeerCertificate.
func NewClientTLSConfig(privKey ed25519.PrivateKey, certDER []byte, knownPeers *peer.KnownPeers) (*tls.Config, error) {
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // We verify via peer_id, not CA chain
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificate(rawCerts, knownPeers)
		},
		NextProtos: []string{"h3"}, // HTTP/3
		MinVersion: tls.VersionTLS13,
	}, nil
}

// NewProxyTLSConfig creates a tls.Config for the Proxy side.
// It requests client certificates and verifies Client peer_id via VerifyPeerCertificate.
func NewProxyTLSConfig(privKey ed25519.PrivateKey, certDER []byte, knownPeers *peer.KnownPeers) (*tls.Config, error) {
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert, // Require cert, verify manually
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificate(rawCerts, knownPeers)
		},
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}, nil
}

// verifyPeerCertificate extracts the Ed25519 public key from the peer's certificate,
// derives peer_id, and checks it against KnownPeers.
func verifyPeerCertificate(rawCerts [][]byte, knownPeers *peer.KnownPeers) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("auth: no certificate presented")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("auth: failed to parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("auth: certificate key is not Ed25519")
	}
	peerID := identity.PeerIDFromPublicKey(pub)
	if knownPeers.Lookup(peerID) == nil {
		return fmt.Errorf("auth: unknown peer_id %s", peerID)
	}
	return nil
}
