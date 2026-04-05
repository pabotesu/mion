// Package keepalive provides per-peer persistent keepalive for MION.
// It sends empty packets at the configured interval to maintain NAT state
// and detect connection loss early (requirements §11).
package keepalive

import (
	"context"
	"log"
	"time"

	"github.com/pabotesu/mion/internal/peer"
)

// Manager runs keepalive loops for all peers that have PersistentKeepalive > 0.
type Manager struct {
	peers *peer.KnownPeers
}

// NewManager creates a keepalive manager.
func NewManager(peers *peer.KnownPeers) *Manager {
	return &Manager{peers: peers}
}

// Run starts the keepalive scheduler. It checks all peers every second
// and sends keepalive packets to those whose interval has elapsed.
// It blocks until the context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.tick()
		}
	}
}

// tick checks each peer and sends a keepalive if needed.
func (m *Manager) tick() {
	now := time.Now()
	for _, p := range m.peers.All() {
		if p.PersistentKeepalive <= 0 {
			continue
		}

		conn := p.GetConn()
		if conn == nil {
			continue
		}

		interval := time.Duration(p.PersistentKeepalive) * time.Second
		lastRecv := p.GetLastReceive()

		// Send keepalive if we haven't received anything within the interval.
		// This keeps NAT mappings alive even when there's no application traffic.
		if now.Sub(lastRecv) >= interval {
			// Send an empty packet as keepalive (same as WireGuard approach)
			if _, err := conn.WritePacket([]byte{}); err != nil {
				log.Printf("[keepalive] failed to send keepalive to peer %s: %v", p.PeerID, err)
			}
		}
	}
}
