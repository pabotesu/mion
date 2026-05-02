// Package proxy implements the MION proxy logic.
// The proxy listens for inbound CONNECT-IP sessions from client peers.
// Each ListenEndpoint creates its own listener: UDP socket for http3, TCP for http2.
package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/pabotesu/mion/config"
	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/peer"
	"github.com/pabotesu/mion/internal/routing"
	h3transport "github.com/pabotesu/mion/internal/transport/h3"
	"github.com/pabotesu/mion/internal/tunnel"
)

// Proxy manages inbound CONNECT-IP sessions from client peers.
type Proxy struct {
	endpoints   []config.ListenEndpoint
	peers       *peer.KnownPeers
	allowedIPs  *routing.AllowedIPs
	tun         tunnel.Device
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	localPrefix netip.Prefix // overlay network prefix (e.g. 100.100.0.0/24)
}

// NewProxy creates a new proxy that will listen on the specified endpoints.
func NewProxy(
	endpoints []config.ListenEndpoint,
	peers *peer.KnownPeers,
	allowedIPs *routing.AllowedIPs,
	tun tunnel.Device,
	tlsConfig *tls.Config,
	localPrefix netip.Prefix,
) *Proxy {
	return &Proxy{
		endpoints:   endpoints,
		peers:       peers,
		allowedIPs:  allowedIPs,
		tun:         tun,
		tlsConfig:   tlsConfig,
		localPrefix: localPrefix,
		quicConfig: &quic.Config{
			EnableDatagrams: true,
			KeepAlivePeriod: 25 * time.Second,
		},
	}
}

// ListenAndServe starts a listener for each configured endpoint and blocks
// until the context is cancelled or one of the listeners fails fatally.
func (p *Proxy) ListenAndServe(ctx context.Context) error {
	if len(p.endpoints) == 0 {
		return fmt.Errorf("proxy: no listen endpoints configured")
	}

	errCh := make(chan error, len(p.endpoints))
	for _, ep := range p.endpoints {
		switch ep.Protocol {
		case "http3":
			go func(ep config.ListenEndpoint) {
				errCh <- p.serveH3(ctx, ep)
			}(ep)
		case "http2":
			return fmt.Errorf("proxy: http2 transport not yet implemented")
		default:
			return fmt.Errorf("proxy: unknown protocol %q", ep.Protocol)
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// serveH3 starts an HTTP/3 (QUIC) listener for a single endpoint.
// It creates its own UDP socket bound to ep.Host:ep.Port.
func (p *Proxy) serveH3(ctx context.Context, ep config.ListenEndpoint) error {
	addr := net.JoinHostPort(ep.Host, fmt.Sprintf("%d", ep.Port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("proxy[h3]: resolve %s: %w", addr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("proxy[h3]: listen UDP %s: %w", addr, err)
	}
	defer udpConn.Close()

	ln, err := quic.ListenEarly(udpConn, p.tlsConfig, p.quicConfig)
	if err != nil {
		return fmt.Errorf("proxy[h3]: listen QUIC %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mion", p.connectIPHandler)

	server := &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}

	log.Printf("[proxy] http3 listening on %s", udpConn.LocalAddr())

	serverErr := make(chan error, 1)
	go func() {
		if err := server.ServeListener(ln); err != nil {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		server.Close()
		return ctx.Err()
	case err := <-serverErr:
		return fmt.Errorf("proxy[h3] %s: %w", addr, err)
	}
}

// connectIPHandler is the HTTP handler for CONNECT-IP requests from clients.
func (p *Proxy) connectIPHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[proxy] incoming CONNECT-IP request from %s", r.RemoteAddr)

	// Identify the peer via mTLS certificate
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		log.Printf("[proxy] no client certificate presented")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		log.Printf("[proxy] client certificate key is not Ed25519")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	peerID := identity.PeerIDFromPublicKey(pub)
	pr := p.peers.Lookup(peerID)
	if pr == nil {
		log.Printf("[proxy] unknown peer public_key=%s peer_id=%s", base64.StdEncoding.EncodeToString(pub), peerID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Build a fixed URI template from the request's :authority header.
	template := uritemplate.MustNew(fmt.Sprintf("https://%s/mion", r.Host))

	cproxy := &connectip.Proxy{}
	req, err := connectip.ParseRequest(r, template)
	if err != nil {
		log.Printf("[proxy] failed to parse CONNECT-IP request: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	conn, err := cproxy.Proxy(w, req)
	if err != nil {
		log.Printf("[proxy] failed to proxy CONNECT-IP: %v", err)
		return
	}

	ctxReq := r.Context()
	if err := conn.AssignAddresses(ctxReq, pr.AllowedIPs); err != nil {
		log.Printf("[proxy] failed to assign addresses to peer %s: %v", pr.DisplayID(), err)
		conn.Close()
		return
	}
	if p.localPrefix.IsValid() {
		route := connectip.IPRoute{
			StartIP:    p.localPrefix.Masked().Addr(),
			EndIP:      lastIP(p.localPrefix),
			IPProtocol: 0,
		}
		if err := conn.AdvertiseRoute(ctxReq, []connectip.IPRoute{route}); err != nil {
			log.Printf("[proxy] failed to advertise route to peer %s: %v", pr.DisplayID(), err)
			conn.Close()
			return
		}
	}

	tc := h3transport.New(conn)
	if old := pr.GetConn(); old != nil {
		_ = old.Close()
	}
	pr.SetConn(tc)
	log.Printf("[proxy] peer %s connected, starting forwarding", pr.DisplayID())

	go func() {
		if err := p.ForwardConnToTUN(pr); err != nil {
			log.Printf("[proxy] forwarding for peer %s ended: %v", pr.DisplayID(), err)
		}
	}()
}

// ForwardTUNToConns reads packets from TUN and sends them to the appropriate
// peer based on AllowedIPs routing.
func (p *Proxy) ForwardTUNToConns(ctx context.Context) error {
	buf := make([]byte, p.tun.MTU())
	for {
		n, err := p.tun.Read(buf)
		if err != nil {
			return fmt.Errorf("proxy: TUN read error: %w", err)
		}
		pkt := buf[:n]

		dstIP := extractDstIP(pkt)
		if !dstIP.IsValid() {
			continue
		}

		peerID, ok := p.allowedIPs.Lookup(dstIP)
		if !ok {
			continue
		}

		pr := p.peers.Lookup(peerID)
		if pr == nil {
			continue
		}

		conn := pr.GetConn()
		if conn == nil {
			continue
		}

		if err := conn.WritePacket(pkt); err != nil {
			log.Printf("[proxy] write to peer %s failed: %v", pr.DisplayID(), err)
			// A WritePacket error means the session is broken.
			// Mark the peer as disconnected so the next client reconnect
			// will re-establish the session via a new CONNECT-IP request.
			pr.ClearConnIf(conn)
		}
	}
}

// ForwardConnToTUN reads packets from a peer\'s CONNECT-IP connection,
// validates the source IP, and writes to the TUN device.
func (p *Proxy) ForwardConnToTUN(pr *peer.Peer) error {
	conn := pr.GetConn()
	if conn == nil {
		return fmt.Errorf("proxy: peer %s has no connection", pr.DisplayID())
	}

	buf := make([]byte, p.tun.MTU())
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil {
			pr.ClearConnIf(conn)
			return fmt.Errorf("proxy: read from peer %s failed: %w", pr.DisplayID(), err)
		}
		pkt := buf[:n]

		// Update last receive timestamp for keepalive/failover tracking
		pr.UpdateLastReceive()

		srcIP := extractSrcIP(pkt)
		if !p.allowedIPs.ValidateSource(srcIP, pr.PeerID) {
			log.Printf("[proxy] dropping packet from peer %s: src %s not in AllowedIPs", pr.DisplayID(), srcIP)
			continue
		}

		if _, err := p.tun.Write(pkt); err != nil {
			log.Printf("[proxy] TUN write error: %v", err)
		}
	}
}

// extractDstIP extracts the destination IP from an IP packet header.
func extractDstIP(pkt []byte) netip.Addr {
	if len(pkt) < 20 {
		return netip.Addr{}
	}
	switch pkt[0] >> 4 {
	case 4:
		return netip.AddrFrom4([4]byte(pkt[16:20]))
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}
		}
		return netip.AddrFrom16([16]byte(pkt[24:40]))
	}
	return netip.Addr{}
}

// extractSrcIP extracts the source IP from an IP packet header.
func extractSrcIP(pkt []byte) netip.Addr {
	if len(pkt) < 20 {
		return netip.Addr{}
	}
	switch pkt[0] >> 4 {
	case 4:
		return netip.AddrFrom4([4]byte(pkt[12:16]))
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}
		}
		return netip.AddrFrom16([16]byte(pkt[8:24]))
	}
	return netip.Addr{}
}

// lastIP returns the last IP address in a prefix (broadcast address for IPv4).
func lastIP(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	bits := prefix.Bits()
	if addr.Is4() {
		a := addr.As4()
		hostBits := 32 - bits
		for i := 3; i >= 0 && hostBits > 0; i-- {
			fill := hostBits
			if fill > 8 {
				fill = 8
			}
			a[i] |= byte((1 << fill) - 1)
			hostBits -= fill
		}
		return netip.AddrFrom4(a)
	}
	a := addr.As16()
	hostBits := 128 - bits
	for i := 15; i >= 0 && hostBits > 0; i-- {
		fill := hostBits
		if fill > 8 {
			fill = 8
		}
		a[i] |= byte((1 << fill) - 1)
		hostBits -= fill
	}
	return netip.AddrFrom16(a)
}
