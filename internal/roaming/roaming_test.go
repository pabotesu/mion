package roaming

import (
	"crypto/sha256"
	"net/netip"
	"testing"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/peer"
)

func makePeerID(s string) identity.PeerID {
	return sha256.Sum256([]byte(s))
}

func TestObserveEndpointDynamic(t *testing.T) {
	d := NewDetector()
	p := &peer.Peer{
		PeerID:             makePeerID("peer1"),
		Endpoint:           netip.MustParseAddrPort("203.0.113.1:51820"),
		ConfiguredEndpoint: false,
	}

	// Same endpoint - no change
	if d.ObserveEndpoint(p, netip.MustParseAddrPort("203.0.113.1:51820")) {
		t.Error("expected no roaming for same endpoint")
	}

	// Different endpoint - should roam
	if !d.ObserveEndpoint(p, netip.MustParseAddrPort("198.51.100.1:51820")) {
		t.Error("expected roaming for different endpoint")
	}
	if p.Endpoint != netip.MustParseAddrPort("198.51.100.1:51820") {
		t.Errorf("endpoint not updated: %v", p.Endpoint)
	}
}

func TestObserveEndpointConfigured(t *testing.T) {
	d := NewDetector()
	p := &peer.Peer{
		PeerID:             makePeerID("peer1"),
		Endpoint:           netip.MustParseAddrPort("203.0.113.1:51820"),
		ConfiguredEndpoint: true, // fixed endpoint
	}

	// Should NOT roam even with different endpoint
	if d.ObserveEndpoint(p, netip.MustParseAddrPort("198.51.100.1:51820")) {
		t.Error("expected no roaming for configured endpoint")
	}
	if p.Endpoint != netip.MustParseAddrPort("203.0.113.1:51820") {
		t.Error("configured endpoint should not have changed")
	}
}

func TestObserveEndpointInvalid(t *testing.T) {
	d := NewDetector()
	p := &peer.Peer{
		PeerID:             makePeerID("peer1"),
		Endpoint:           netip.MustParseAddrPort("203.0.113.1:51820"),
		ConfiguredEndpoint: false,
	}

	if d.ObserveEndpoint(p, netip.AddrPort{}) {
		t.Error("expected no roaming for invalid endpoint")
	}
}

func TestObserveEndpointIPv6(t *testing.T) {
	d := NewDetector()
	p := &peer.Peer{
		PeerID:             makePeerID("peer1"),
		Endpoint:           netip.MustParseAddrPort("[fd00::1]:51820"),
		ConfiguredEndpoint: false,
	}

	if !d.ObserveEndpoint(p, netip.MustParseAddrPort("[fd00::2]:51820")) {
		t.Error("expected IPv6 roaming")
	}
	if p.Endpoint != netip.MustParseAddrPort("[fd00::2]:51820") {
		t.Errorf("endpoint not updated: %v", p.Endpoint)
	}
}
