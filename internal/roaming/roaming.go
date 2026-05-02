// Package roaming provides endpoint roaming detection for MION.
// When a peer's observed source address changes, the endpoint is updated
// if the peer allows roaming (i.e., ConfiguredEndpoint == false).
// This implements requirements section 12.
package roaming

import (
	"log"
	"net/netip"

	"github.com/pabotesu/mion/internal/peer"
)

// Detector checks if a peer's source endpoint has changed and updates it.
type Detector struct{}

// NewDetector creates a roaming detector.
func NewDetector() *Detector {
	return &Detector{}
}

// ObserveEndpoint is called when we receive a valid packet from a peer.
// If the observed endpoint differs from the stored one and roaming is allowed,
// the endpoint is updated.
//
// HTTP/2 peers are excluded: TCP sessions are tied to a specific address, so
// if the source address changes the session is already broken. Roaming only
// applies to UDP/QUIC-based (HTTP/3) peers.
//
// Returns true if the endpoint was updated (roaming occurred).
func (d *Detector) ObserveEndpoint(p *peer.Peer, observed netip.AddrPort) bool {
	if !observed.IsValid() {
		return false
	}

	// HTTP/2 peers run over TCP; roaming is meaningless (requirements §14).
	if p.EndpointScheme == "http2" {
		return false
	}

	// If endpoint is configured (fixed), don't roam (requirements 12.2)
	if p.ConfiguredEndpoint {
		return false
	}

	// Check if endpoint has changed
	if p.Endpoint == observed {
		return false
	}

	// Update endpoint (roaming = endpoint overwrite, requirements 12.4)
	old := p.Endpoint
	if p.SetEndpoint(observed) {
		log.Printf("[roaming] peer %s endpoint changed: %s -> %s", p.PeerID, old, observed)
		return true
	}

	return false
}
