// Package mion provides the core orchestration for the MION daemon.
// It owns the single shared UDP socket, manages the peer table and AllowedIPs
// routing table, and coordinates the Client/Proxy roles with TUN forwarding.
package mion

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/pabotesu/mion/config"
	"github.com/pabotesu/mion/internal/auth"
	"github.com/pabotesu/mion/internal/client"
	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/keepalive"
	"github.com/pabotesu/mion/internal/proxy"
	"github.com/pabotesu/mion/peer"
	"github.com/pabotesu/mion/internal/routing"
	"github.com/pabotesu/mion/internal/tunnel"
)

// Role determines whether this MION instance acts as Client, Proxy, or both.
type Role int

const (
	RoleClient Role = iota
	RoleProxy
)

// Config holds the runtime configuration for a Mion instance.
type Config struct {
	// InterfaceName is the TUN device name (e.g., "mion0").
	InterfaceName string

	// ListenPort is the UDP port for the shared socket (client role). 0 = OS-assigned.
	ListenPort int

	// ListenEndpoints is the list of protocol+address pairs the proxy listens on.
	// Each entry is parsed from ListenPort in the config file (proxy role).
	ListenEndpoints []config.ListenEndpoint

	// PrivateKey is the Ed25519 private key for this node.
	PrivateKey ed25519.PrivateKey

	// Address is the IP address/prefix assigned to the TUN device.
	Address netip.Prefix

	// Role determines Client or Proxy behavior.
	Role Role
}

// Mion is the core MION instance. It owns all shared resources.
type Mion struct {
	cfg         Config
	peerID      identity.PeerID
	udpConn     *net.UDPConn
	tun         tunnel.Device
	peers       *peer.KnownPeers
	allowedIPs  *routing.AllowedIPs
	cancel      context.CancelFunc
	ctx         context.Context
	reconnectFn func(context.Context, *peer.Peer) error
	client      *client.Client
	clientReady chan struct{} // closed when m.client is set (client role only)
}

// New creates and initializes a Mion instance.
// For proxy role: no shared UDP socket is created (each ListenEndpoint creates its own).
// For client role: a single shared UDP socket is created for all outbound dials.
func New(cfg Config) (*Mion, error) {
	// Derive our own PeerID
	pub := cfg.PrivateKey.Public().(ed25519.PublicKey)
	peerID := identity.PeerIDFromPublicKey(pub)
	log.Printf("[mion] local peer_id: %s", peerID)

	// Create TUN device
	mtu := 1350 // QUIC+HTTP3+CONNECT-IP overhead (~150 bytes) subtracted from 1500
	tun, err := tunnel.NewDevice(cfg.InterfaceName, mtu)
	if err != nil {
		// On non-Linux (dev), NewDevice returns a StubDevice + error.
		// We log the warning but continue with the stub.
		log.Printf("[mion] TUN warning: %v", err)
	}

	return &Mion{
		cfg:         cfg,
		peerID:      peerID,
		tun:         tun,
		peers:       peer.NewKnownPeers(),
		allowedIPs:  routing.NewAllowedIPs(),
		clientReady: make(chan struct{}),
	}, nil
}

// PeerID returns this node's PeerID.
func (m *Mion) PeerID() identity.PeerID { return m.peerID }

// Role returns the role name for UAPI display.
func (m *Mion) Role() string {
	if m.cfg.Role == RoleProxy {
		return "proxy"
	}
	return "client"
}

// ListenEndpoints returns the listen endpoints as URL strings for UAPI display.
func (m *Mion) ListenEndpoints() []string {
	var eps []string
	for _, ep := range m.cfg.ListenEndpoints {
		eps = append(eps, fmt.Sprintf("%s://:%d", ep.Protocol, ep.Port))
	}
	return eps
}

// ListenPort returns the UDP listen port (client role only).
// For proxy role, returns the first http3 port from ListenEndpoints (or 0).
func (m *Mion) ListenPort() int {
	if m.udpConn != nil {
		addr := m.udpConn.LocalAddr().(*net.UDPAddr)
		return addr.Port
	}
	// Proxy role: derive from ListenEndpoints
	for _, ep := range m.cfg.ListenEndpoints {
		if ep.Protocol == "http3" {
			return ep.Port
		}
	}
	return 0
}

// UDPConn returns the shared UDP socket.
func (m *Mion) UDPConn() *net.UDPConn { return m.udpConn }

// TUN returns the TUN device.
func (m *Mion) TUN() tunnel.Device { return m.tun }

// Peers returns the KnownPeers registry.
func (m *Mion) Peers() *peer.KnownPeers { return m.peers }

// AllowedIPs returns the AllowedIPs routing table.
func (m *Mion) AllowedIPs() *routing.AllowedIPs { return m.allowedIPs }

// AddPeer registers a peer and populates the AllowedIPs table.
func (m *Mion) AddPeer(p *peer.Peer) error {
	// Auto-derive PeerID from PublicKey if not set by the caller.
	if p.PublicKey != nil && p.PeerID == (identity.PeerID{}) {
		p.PeerID = identity.PeerIDFromPublicKey(p.PublicKey)
	}
	if err := m.peers.Add(p); err != nil {
		return err
	}
	for _, prefix := range p.AllowedIPs {
		m.allowedIPs.Insert(prefix, p.PeerID)
	}
	log.Printf("[mion] added peer %s with %d allowed prefixes", p.DisplayID(), len(p.AllowedIPs))
	return nil
}

// RemovePeer unregisters a peer and removes its AllowedIPs entries.
func (m *Mion) RemovePeer(id identity.PeerID) {
	m.allowedIPs.Remove(id)
	m.peers.Remove(id)
	log.Printf("[mion] removed peer %s", id)
}

// UpdatePeerAllowedIPs replaces the AllowedIPs for an existing peer and
// atomically updates the routing table to match.
func (m *Mion) UpdatePeerAllowedIPs(id identity.PeerID, prefixes []netip.Prefix) error {
	p := m.peers.Lookup(id)
	if p == nil {
		return fmt.Errorf("mion: peer %s not found", id)
	}
	// Remove all existing routing entries for this peer.
	m.allowedIPs.Remove(id)
	// Insert the new prefixes.
	for _, prefix := range prefixes {
		m.allowedIPs.Insert(prefix, id)
	}
	log.Printf("[mion] updated allowed_ips for peer %s: %d prefixes", p.DisplayID(), len(prefixes))
	return nil
}

// ReconnectPeer tears down the existing connection for a peer and
// re-establishes it using the peer's current endpoint.
// This is called when the endpoint is changed at runtime via UAPI.
func (m *Mion) ReconnectPeer(id identity.PeerID) error {
	p := m.peers.Lookup(id)
	if p == nil {
		return fmt.Errorf("mion: peer %s not found", id)
	}

	// Close existing connection
	p.SetConn(nil)
	log.Printf("[mion] disconnecting peer %s for endpoint change", p.DisplayID())

	if m.reconnectFn == nil {
		// Proxy role or not yet running — no active reconnect needed
		return nil
	}

	// Reconnect in the background
	go func() {
		ctx := m.ctx
		if ctx == nil {
			return
		}
		if err := m.reconnectFn(ctx, p); err != nil {
			log.Printf("[mion] reconnect to peer %s failed: %v", p.DisplayID(), err)
		} else {
			log.Printf("[mion] reconnected to peer %s at %s", p.DisplayID(), p.Endpoint)
		}
	}()

	return nil
}

// ClientReady returns a channel that is closed once the client is initialized
// (i.e. m.client has been set in runClient). External callers (e.g. MALON)
// should wait on this channel before calling StartForwardConnToTUN.
// For the proxy role the channel is never closed; callers should also select
// on ctx.Done() to avoid blocking indefinitely.
func (m *Mion) ClientReady() <-chan struct{} {
	return m.clientReady
}

// StartForwardConnToTUN starts a goroutine that reads packets from p.Conn
// (set via peer.Peer.SetConn) and writes them to TUN.
// When the connection is closed the goroutine exits silently — no retry is
// triggered, because the caller (MALON) is responsible for managing the relay
// connection lifecycle.
// This is intended for relay connections injected by MALON: after calling
// peer.Peer.SetConn(relayConn), call this method to activate Conn→TUN forwarding.
// TUN→Conn forwarding works automatically via AllowedIPs routing without any
// additional call.
func (m *Mion) StartForwardConnToTUN(ctx context.Context, p *peer.Peer) {
	if m.client == nil {
		log.Printf("[mion] StartForwardConnToTUN: client not initialized (proxy role?)")
		return
	}
	go func() {
		if err := m.client.ForwardConnToTUN(p); err != nil {
			log.Printf("[mion] relay conn to peer %s closed: %v", p.DisplayID(), err)
		}
	}()
}

// Close tears down the Mion instance.

func (m *Mion) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	var errs []error
	if m.tun != nil {
		if err := m.tun.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tun close: %w", err))
		}
	}
	if m.udpConn != nil {
		if err := m.udpConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("udp close: %w", err))
		}
	}
	log.Printf("[mion] shutdown complete")
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Run starts the MION instance. It generates the self-signed certificate,
// creates TLS configs, and launches the Client or Proxy role with forwarding loops.
// It blocks until the context is cancelled.
func (m *Mion) Run(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.ctx = ctx
	defer m.Close()

	// Configure TUN address from the [Interface] Address field
	if m.cfg.Address.IsValid() {
		ipNet := prefixToIPNet(m.cfg.Address)
		if err := tunnel.ConfigureAddress(m.tun.Name(), ipNet); err != nil {
			return fmt.Errorf("mion: failed to configure TUN address: %w", err)
		}
		log.Printf("[mion] configured %s with address %s", m.tun.Name(), m.cfg.Address)
	}

	// Generate self-signed certificate from our private key
	_, certDER, err := identity.SelfSignedCert(m.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("mion: failed to generate certificate: %w", err)
	}
	log.Printf("[mion] generated self-signed certificate for %s", m.peerID)

	switch m.cfg.Role {
	case RoleClient:
		return m.runClient(ctx, certDER)
	case RoleProxy:
		return m.runProxy(ctx, certDER)
	default:
		return fmt.Errorf("mion: unknown role %d", m.cfg.Role)
	}
}

// runClient starts the MION client role: creates the shared UDP socket,
// dials all configured peers, then runs the TUN→Conn forwarding loop,
// keepalive, and failover until context cancellation.
func (m *Mion) runClient(ctx context.Context, certDER []byte) error {
	// Client creates a single shared UDP socket for all outbound QUIC dials.
	listenAddr := &net.UDPAddr{Port: m.cfg.ListenPort}
	udpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("mion: failed to create UDP socket: %w", err)
	}
	m.udpConn = udpConn
	log.Printf("[mion] client socket: %s", udpConn.LocalAddr())

	tlsCfg, err := auth.NewClientTLSConfig(m.cfg.PrivateKey, certDER, m.peers)
	if err != nil {
		return fmt.Errorf("mion: client TLS config: %w", err)
	}

	c := client.NewClient(m.udpConn, m.peers, m.allowedIPs, m.tun, tlsCfg)
	m.client = c
	close(m.clientReady) // signal that m.client is ready for external callers
	if err := c.DialAllPeers(ctx); err != nil {
		return fmt.Errorf("mion: dial peers: %w", err)
	}

	// Start keepalive manager (requirements §11)
	ka := keepalive.NewManager(m.peers)
	go ka.Run(ctx)

	// Reconnect function for UAPI endpoint changes.
	// Normal reconnection is handled by retryDial inside client.DialAllPeers.
	m.reconnectFn = func(rctx context.Context, p *peer.Peer) error {
		if err := c.DialPeer(rctx, p); err != nil {
			return err
		}
		p.SetActive(true)
		go func() {
			if fwErr := c.ForwardConnToTUN(p); fwErr != nil {
				log.Printf("[client] peer %s disconnected after UAPI reconnect, will retry", p.DisplayID())
				c.StartRetry(rctx, p)
			}
		}()
		return nil
	}

	// Run TUN → Conn forwarding (blocks until context done or error)
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.ForwardTUNToConn(ctx)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// runProxy starts the MION proxy role: listens for inbound CONNECT-IP sessions,
// runs the TUN→Conns forwarding loop, and starts keepalive until context cancellation.
func (m *Mion) runProxy(ctx context.Context, certDER []byte) error {
	tlsCfg, err := auth.NewProxyTLSConfig(m.cfg.PrivateKey, certDER, m.peers)
	if err != nil {
		return fmt.Errorf("mion: proxy TLS config: %w", err)
	}

	p := proxy.NewProxy(m.cfg.ListenEndpoints, m.peers, m.allowedIPs, m.tun, tlsCfg, m.cfg.Address)

	// Start keepalive manager (requirements §11)
	ka := keepalive.NewManager(m.peers)
	go ka.Run(ctx)

	// Start TUN → Conns forwarding in background
	errCh := make(chan error, 2)
	go func() {
		errCh <- p.ForwardTUNToConns(ctx)
	}()

	// ListenAndServe blocks until context done
	go func() {
		errCh <- p.ListenAndServe(ctx)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// prefixToIPNet converts a netip.Prefix to net.IPNet for use with
// tunnel.ConfigureAddress which uses the older net.IPNet type.
func prefixToIPNet(prefix netip.Prefix) net.IPNet {
	addr := prefix.Addr()
	ip := addr.As16()
	var netIP net.IP
	if addr.Is4() {
		netIP = net.IP(ip[12:16]).To4()
	} else {
		netIP = net.IP(ip[:])
	}
	bits := prefix.Bits()
	var totalBits int
	if addr.Is4() {
		totalBits = 32
	} else {
		totalBits = 128
	}
	mask := net.CIDRMask(bits, totalBits)
	return net.IPNet{IP: netIP, Mask: mask}
}
