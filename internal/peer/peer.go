// Package peer manages Peer state and the KnownPeers registry.
package peer

import (
	"net/netip"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"github.com/pabotesu/mion/internal/identity"
)

// Peer represents a known peer in the MION network.
// This maps directly to requirements Section 10.
type Peer struct {
	// PeerID is the public-key-based identity (requirements 10.1).
	PeerID identity.PeerID

	// AllowedIPs defines which prefixes this peer is responsible for (requirements 10.2).
	// Used for outbound routing (dst lookup) and inbound source validation.
	AllowedIPs []netip.Prefix

	// Endpoint is the current connection target for this peer (requirements 10.3).
	// If set via config: fixed endpoint, no roaming.
	// If unset (zero value): dynamic endpoint, roaming allowed.
	Endpoint netip.AddrPort

	// ConfiguredEndpoint indicates whether Endpoint was set via config file.
	// When true: endpoint is fixed, roaming disabled.
	// When false: endpoint is dynamic, updated by observation.
	ConfiguredEndpoint bool

	// Active indicates whether this peer is currently usable on the data plane (requirements 10.4).
	Active bool

	// Conn is the CONNECT-IP session with this peer. Nil if not connected.
	Conn *connectip.Conn

	// PersistentKeepalive is the keepalive interval in seconds. 0 means disabled.
	PersistentKeepalive int

	// LastHandshake is the time the CONNECT-IP session was established.
	LastHandshake time.Time

	// LastReceive is the time we last received a valid packet from this peer.
	LastReceive time.Time

	// mu protects mutable fields (Endpoint, Active, Conn, timestamps).
	mu sync.RWMutex

	// retrying indicates whether a background retry loop is currently running.
	retrying bool
}

// SetEndpoint updates the peer's endpoint. Only allowed if not a configured endpoint.
func (p *Peer) SetEndpoint(ep netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ConfiguredEndpoint {
		return false
	}
	p.Endpoint = ep
	return true
}

// SetActive updates the peer's active status.
func (p *Peer) SetActive(active bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Active = active
}

// SetConn sets the CONNECT-IP connection for this peer.
func (p *Peer) SetConn(conn *connectip.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Conn = conn
	p.Active = conn != nil
	if conn != nil {
		p.LastHandshake = time.Now()
		p.LastReceive = time.Now()
	}
}

// ClearConnIf clears the peer connection only when the current connection
// matches conn. This avoids stale forwarding goroutines clearing a newly
// established connection.
func (p *Peer) ClearConnIf(conn *connectip.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Conn != conn {
		return false
	}
	p.Conn = nil
	p.Active = false
	return true
}

// GetConn returns the current CONNECT-IP connection (may be nil).
func (p *Peer) GetConn() *connectip.Conn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Conn
}

// UpdateLastReceive records that we received a valid packet from this peer.
func (p *Peer) UpdateLastReceive() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastReceive = time.Now()
}

// GetLastReceive returns the last receive timestamp.
func (p *Peer) GetLastReceive() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.LastReceive
}

// IsExpired returns true if we haven't received any packet within the given timeout.
func (p *Peer) IsExpired(timeout time.Duration) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.Active {
		return true
	}
	return time.Since(p.LastReceive) > timeout
}

// TryStartRetry marks this peer as having an active retry loop.
// It returns false when a retry loop is already running.
func (p *Peer) TryStartRetry() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retrying {
		return false
	}
	p.retrying = true
	return true
}

// StopRetry clears the retry-loop marker for this peer.
func (p *Peer) StopRetry() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retrying = false
}
