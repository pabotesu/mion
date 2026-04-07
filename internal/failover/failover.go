// Package failover provides endpoint failover for MION.
// When the current endpoint becomes unreachable, the failover manager
// attempts to reconnect using alternative endpoint candidates.
// This implements requirements section 13.
package failover

import (
	"context"
	"log"
	"time"

	"github.com/pabotesu/mion/internal/peer"
)

// ReconnectFunc is called to re-establish a connection to a peer.
// The caller (mion core) provides this to abstract the dial logic.
type ReconnectFunc func(ctx context.Context, p *peer.Peer) error

// Manager monitors peers for connection loss and triggers failover.
type Manager struct {
	peers     *peer.KnownPeers
	reconnect ReconnectFunc
	timeout   time.Duration
}

// NewManager creates a failover manager.
// timeout is how long without receiving packets before a peer is considered dead.
func NewManager(peers *peer.KnownPeers, reconnect ReconnectFunc, timeout time.Duration) *Manager {
	return &Manager{
		peers:     peers,
		reconnect: reconnect,
		timeout:   timeout,
	}
}

// Run starts the failover monitor. It checks all peers periodically
// and triggers reconnection for those that appear dead.
// It blocks until the context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.check(ctx)
		}
	}
}

// check inspects all peers and triggers failover for dead ones.
func (m *Manager) check(ctx context.Context) {
	for _, p := range m.peers.All() {
		conn := p.GetConn()

		// Only trigger failover if the peer was connected but the
		// connection has been lost (conn == nil && was previously active),
		// or if the peer is marked inactive by the keepalive monitor.
		if conn != nil {
			// Connection object still exists — QUIC session is alive.
			// No failover needed regardless of LastReceive.
			continue
		}

		if !p.Active {
			// Already inactive and no connection — nothing to failover.
			continue
		}

		// Peer is marked active but has no connection — connection was lost.
		log.Printf("[failover] peer %s connection lost, attempting reconnect", p.PeerID)

		// Close existing connection
		p.SetConn(nil)

		// Attempt reconnection (non-blocking)
		go func(pr *peer.Peer) {
			reconnCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := m.reconnect(reconnCtx, pr); err != nil {
				log.Printf("[failover] peer %s reconnect failed: %v", pr.PeerID, err)
			} else {
				log.Printf("[failover] peer %s reconnected successfully", pr.PeerID)
			}
		}(p)
	}
}
