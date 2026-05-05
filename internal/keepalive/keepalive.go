// Package keepalive provides per-peer liveness monitoring for MION.
//
// HTTP/3 peers: actual keepalive packets are sent automatically by QUIC's
// KeepAlivePeriod; this manager tracks receive timestamps and closes dead
// connections so that client.StartRetry can reconnect.
//
// HTTP/2 peers: QUIC is not used, so this manager sends an empty capsule
// (zero-length WritePacket) at each keepalive interval to keep the TCP
// session and any NAT mapping alive.
// If no pong is received within pongTimeout after the first ping, the
// connection is closed so that client.StartRetry can reconnect.
package keepalive

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/peer"
)

// keepaliveInterval is the fixed interval for sending HTTP/2 keepalive capsules.
const keepaliveInterval = 10 * time.Second

// pongTimeout is the maximum time to wait for a Pong after sending a Ping.
const pongTimeout = 5 * time.Second

// Manager monitors peer liveness and closes dead connections so that
// client.StartRetry can detect the failure and reconnect.
type Manager struct {
	peers      *peer.KnownPeers
	mu         sync.Mutex
	pingSentAt map[identity.PeerID]time.Time
}

// NewManager creates a keepalive manager.
func NewManager(peers *peer.KnownPeers) *Manager {
	return &Manager{
		peers:      peers,
		pingSentAt: make(map[identity.PeerID]time.Time),
	}
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
				// Send Ping
				if err := conn.WritePacket([]byte{}); err != nil {
					log.Printf("[keepalive] peer %s http2 ping failed: %v", p.PeerID, err)
				} else {
					// Record first ping sent time (don't overwrite if already waiting)
					m.mu.Lock()
					if _, exists := m.pingSentAt[p.PeerID]; !exists {
						m.pingSentAt[p.PeerID] = now
					}
					m.mu.Unlock()
				}
			} else {
				// Data received recently — clear ping tracking
				m.mu.Lock()
				delete(m.pingSentAt, p.PeerID)
				m.mu.Unlock()
			}

			// Pong timeout: close if no response within pongTimeout after first Ping
			m.mu.Lock()
			pingSent, waiting := m.pingSentAt[p.PeerID]
			m.mu.Unlock()
			if waiting && now.Sub(pingSent) >= pongTimeout {
				log.Printf("[keepalive] peer %s pong timeout after %s, closing connection", p.PeerID, pongTimeout)
				_ = conn.Close()
				m.mu.Lock()
				delete(m.pingSentAt, p.PeerID)
				m.mu.Unlock()
				continue
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
