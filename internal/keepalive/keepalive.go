// Package keepalive provides per-peer persistent keepalive for MION.
// QUIC's built-in KeepAlivePeriod handles the actual keepalive packets.
// This manager monitors peer liveness by tracking receive timestamps
// (requirements §11).
package keepalive

import (
	"context"
	"time"

	"github.com/pabotesu/mion/internal/peer"
)

// Manager monitors peer liveness. Actual keepalive packets are sent by
// QUIC's KeepAlivePeriod; this manager only tracks receive timestamps
// so that the failover manager can detect dead peers.
type Manager struct {
	peers *peer.KnownPeers
}

// NewManager creates a keepalive manager.
func NewManager(peers *peer.KnownPeers) *Manager {
	return &Manager{peers: peers}
}

// Run starts the keepalive monitor. It checks all peers every second
// and marks inactive peers whose last receive exceeds 2× the interval.
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

// tick checks each peer's liveness based on receive timestamps.
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

		// If no data received for 2× interval, mark peer as inactive
		// so failover manager can trigger reconnection.
		interval := time.Duration(p.PersistentKeepalive) * time.Second
		lastRecv := p.GetLastReceive()
		if !lastRecv.IsZero() && now.Sub(lastRecv) >= 2*interval {
			p.SetActive(false)
		}
	}
}
