// Package routing implements the AllowedIPs routing table.
// It performs longest-prefix-match to map destination IPs to peers,
// and validates source IPs against a peer's allowed prefixes.
package routing

import (
	"net/netip"
	"sync"

	"github.com/pabotesu/mion/internal/identity"
)

// AllowedIPs maps IP prefixes to peer_ids.
// Used for:
//   - Outbound: dst IP → which peer to send to (longest prefix match)
//   - Inbound: src IP + peer_id → is this source valid for this peer?
type AllowedIPs struct {
	mu      sync.RWMutex
	entries []entry
}

type entry struct {
	prefix netip.Prefix
	peerID identity.PeerID
}

// NewAllowedIPs creates an empty AllowedIPs table.
func NewAllowedIPs() *AllowedIPs {
	return &AllowedIPs{}
}

// Insert adds a prefix→peerID mapping.
func (a *AllowedIPs) Insert(prefix netip.Prefix, peerID identity.PeerID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, entry{prefix: prefix, peerID: peerID})
}

// Remove removes all entries for a given peerID.
func (a *AllowedIPs) Remove(peerID identity.PeerID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	filtered := a.entries[:0]
	for _, e := range a.entries {
		if e.peerID != peerID {
			filtered = append(filtered, e)
		}
	}
	a.entries = filtered
}

// Lookup finds the peer responsible for the given IP address
// using longest-prefix-match.
func (a *AllowedIPs) Lookup(addr netip.Addr) (identity.PeerID, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var bestPeerID identity.PeerID
	bestBits := -1
	for _, e := range a.entries {
		if e.prefix.Contains(addr) {
			if bits := e.prefix.Bits(); bits > bestBits {
				bestBits = bits
				bestPeerID = e.peerID
			}
		}
	}
	if bestBits < 0 {
		return identity.PeerID{}, false
	}
	return bestPeerID, true
}

// ValidateSource checks whether the given source IP is allowed for the specified peer.
func (a *AllowedIPs) ValidateSource(src netip.Addr, peerID identity.PeerID) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, e := range a.entries {
		if e.peerID == peerID && e.prefix.Contains(src) {
			return true
		}
	}
	return false
}
