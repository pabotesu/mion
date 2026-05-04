// Package keepalive provides per-peer liveness monitoring for MION.
//
// HTTP/3 peers: actual keepalive packets are sent automatically by QUIC's
// KeepAlivePeriod; this manager tracks receive timestamps and closes dead
// connections so that client.StartRetry can reconnect.
//
// HTTP/2 peers: QUIC is not used, so this manager sends an empty capsule
// (zero-length WritePacket) at each keepalive interval to keep the TCP
// session and any NAT mapping alive.
// If no data is received for 2× the interval, the connection is closed so
// that client.StartRetry can reconnect.
package keepalive

import (
	"context"
	"log"
	"time"

	"github.com/pabotesu/mion/internal/peer"
)

// keepaliveInterval is the fixed interval for liveness checks and HTTP/2 keepalive capsules.
const keepaliveInterval = 25 * time.Second

// Manager monitors peer liveness and closes dead connections so that
// client.StartRetry can detect the failure and reconnect.
type Manager struct {
	peers *peer.KnownPeers
}

// NewManager creates a keepalive manager.
func NewManager(peers *peer.KnownPeers) *Manager {
	return &Manager{peers: peers}
}

// Run starts the keepalive monitor. It checks all peers every second
// and closes connections that have been silent for 2× keepaliveInterval.
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

// tick checks each peer's liveness and sends HTTP/2 keepalive capsules.
func (m *Manager) tick() {
	now := time.Now()
	for _, p := range m.peers.All() {
		conn := p.GetConn()
		if conn == nil {
			continue
		}

		// HTTP/2 peers: send an empty capsule to keep the TCP session alive.
		if p.GetEndpointScheme() == "http2" {
			lastRecv := p.GetLastReceive()
			if lastRecv.IsZero() || now.Sub(lastRecv) >= keepaliveInterval {
				if err := conn.WritePacket([]byte{}); err != nil {
					log.Printf("[keepalive] peer %s http2 ping failed: %v", p.PeerID, err)
				}
			}
		}

		// HTTP/2 only: if no data received for 2× interval, close the connection.
		// HTTP/3 peers rely on QUIC KeepAlivePeriod for liveness; ReadPacket will
		// return an error automatically when the QUIC connection dies.
		if p.GetEndpointScheme() == "http2" {
			lastRecv := p.GetLastReceive()
			if !lastRecv.IsZero() && now.Sub(lastRecv) >= 2*keepaliveInterval {
				log.Printf("[keepalive] peer %s silent for %s, closing connection", p.PeerID, now.Sub(lastRecv).Round(time.Second))
				_ = conn.Close()
			}
		}
	}
}
