// Package keepalive provides per-peer persistent keepalive for MION.
//
// HTTP/3 peers: actual keepalive packets are sent automatically by QUIC's
// KeepAlivePeriod; this manager only tracks receive timestamps so that the
// failover manager can detect dead peers.
//
// HTTP/2 peers: QUIC is not used, so this manager sends an empty capsule
// (zero-length WritePacket) at each keepalive interval to keep the TCP
// session and any NAT mapping alive (requirements §11).
package keepalive

import (
	"context"
	"log"
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
// For HTTP/2 peers it also sends an empty keepalive capsule.
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

		// HTTP/2 peers: QUIC KeepAlivePeriod is not available, so we send
		// an empty capsule at each interval to keep the TCP session alive.
		if p.EndpointScheme == "http2" {
			lastRecv := p.GetLastReceive()
			if lastRecv.IsZero() || now.Sub(lastRecv) >= interval {
				if err := conn.WritePacket([]byte{}); err != nil {
					log.Printf("[keepalive] peer %s http2 ping failed: %v", p.PeerID, err)
				}
			}
		}

		// If no data received for 2× interval, mark peer as inactive
		// so failover manager can trigger reconnection.
		lastRecv := p.GetLastReceive()
		if !lastRecv.IsZero() && now.Sub(lastRecv) >= 2*interval {
			p.SetActive(false)
		}
	}
}
