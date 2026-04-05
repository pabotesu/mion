package peer

import (
	"fmt"
	"sync"

	"github.com/pabotesu/mion/internal/identity"
)

// KnownPeers is a thread-safe registry of peers indexed by PeerID.
// Both Client and Proxy use this to manage their allowed peers.
type KnownPeers struct {
	mu    sync.RWMutex
	peers map[identity.PeerID]*Peer
}

// NewKnownPeers creates an empty KnownPeers registry.
func NewKnownPeers() *KnownPeers {
	return &KnownPeers{
		peers: make(map[identity.PeerID]*Peer),
	}
}

// Add registers a peer. Returns an error if the peer_id already exists.
func (kp *KnownPeers) Add(p *Peer) error {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	if _, exists := kp.peers[p.PeerID]; exists {
		return fmt.Errorf("peer: peer_id %s already registered", p.PeerID)
	}
	kp.peers[p.PeerID] = p
	return nil
}

// Remove unregisters a peer by PeerID.
func (kp *KnownPeers) Remove(id identity.PeerID) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	delete(kp.peers, id)
}

// Lookup returns a peer by PeerID, or nil if not found.
func (kp *KnownPeers) Lookup(id identity.PeerID) *Peer {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return kp.peers[id]
}

// All returns a snapshot of all registered peers.
func (kp *KnownPeers) All() []*Peer {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	result := make([]*Peer, 0, len(kp.peers))
	for _, p := range kp.peers {
		result = append(result, p)
	}
	return result
}

// Len returns the number of registered peers.
func (kp *KnownPeers) Len() int {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return len(kp.peers)
}
