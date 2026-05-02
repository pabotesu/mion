// Package peer manages Peer state and the KnownPeers registry.
package peer

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/transport"
)

// Peer represents a known peer in the MION network.
// This maps directly to requirements Section 10.
type Peer struct {
	// PublicKey is the Ed25519 public key for this peer.
	// It may be nil when the peer was provisioned only by peer_id.
	PublicKey ed25519.PublicKey

	// PeerID is the public-key-based identity (requirements 10.1).
	PeerID identity.PeerID

	// AllowedIPs defines which prefixes this peer is responsible for (requirements 10.2).
	// Used for outbound routing (dst lookup) and inbound source validation.
	AllowedIPs []netip.Prefix

	// Endpoint is the current connection target for this peer (requirements 10.3).
	// If set via config: fixed endpoint, no roaming.
	// If unset (zero value): dynamic endpoint, roaming allowed.
	Endpoint netip.AddrPort

	// EndpointScheme is the transport protocol for this peer's endpoint.
	// "http3" (QUIC/CONNECT-IP) or "http2" (TLS+TCP/CONNECT-IP).
	// Derived from the Endpoint URI scheme in the config file.
	EndpointScheme string

	// ConfiguredEndpoint indicates whether Endpoint was set via config file.
	// When true: endpoint is fixed, roaming disabled.
	// When false: endpoint is dynamic, updated by observation.
	ConfiguredEndpoint bool

	// Active indicates whether this peer is currently usable on the data plane (requirements 10.4).
	Active bool

	// Conn is the active tunnel session with this peer. Nil if not connected.
	// The concrete type depends on the transport in use (h3.Conn, h2.Conn, etc.).
	Conn transport.TunnelConn

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

// SetConn stores the active tunnel session for this peer.
func (p *Peer) SetConn(conn transport.TunnelConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Conn = conn
	p.Active = conn != nil
	if conn != nil {
		p.LastHandshake = time.Now()
		p.LastReceive = time.Now()
	}
}

// SetPublicKey stores the peer's Ed25519 public key.
func (p *Peer) SetPublicKey(pub ed25519.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(pub) != ed25519.PublicKeySize {
		p.PublicKey = nil
		return
	}
	p.PublicKey = append(ed25519.PublicKey(nil), pub...)
}

// DisplayID returns a human-readable identifier for logs.
// It includes both public_key and peer_id when the public key is known.
func (p *Peer) DisplayID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.PublicKey) == ed25519.PublicKeySize {
		return fmt.Sprintf("public_key=%s peer_id=%s", base64.StdEncoding.EncodeToString(p.PublicKey), p.PeerID)
	}
	return fmt.Sprintf("peer_id=%s", p.PeerID)
}

// ClearConnIf clears the peer connection only when the current connection
// matches conn. This avoids stale forwarding goroutines clearing a newly
// established connection.
func (p *Peer) ClearConnIf(conn transport.TunnelConn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Conn != conn {
		return false
	}
	p.Conn = nil
	p.Active = false
	return true
}

// GetConn returns the current tunnel session (may be nil).
func (p *Peer) GetConn() transport.TunnelConn {
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
