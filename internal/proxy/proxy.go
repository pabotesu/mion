// Package proxy implements the MION proxy logic.
// The proxy listens for inbound CONNECT-IP sessions from client peers
// over a single shared UDP socket.
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

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/peer"
	"github.com/pabotesu/mion/internal/routing"
	h3transport "github.com/pabotesu/mion/internal/transport/h3"
	"github.com/pabotesu/mion/internal/tunnel"
)

// Proxy manages inbound CONNECT-IP sessions from client peers.
type Proxy struct {
	udpConn     *net.UDPConn
	peers       *peer.KnownPeers
	allowedIPs  *routing.AllowedIPs
	tun         tunnel.Device
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	localPrefix netip.Prefix // overlay network prefix (e.g. 100.100.0.0/24)
}

// NewProxy creates a new proxy that listens on the provided shared UDP socket.
func NewProxy(
	udpConn *net.UDPConn,
	peers *peer.KnownPeers,
	allowedIPs *routing.AllowedIPs,
	tun tunnel.Device,
	tlsConfig *tls.Config,
	localPrefix netip.Prefix,
) *Proxy {
	return &Proxy{
		udpConn:     udpConn,
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

// ListenAndServe starts the HTTP/3 server on the shared UDP socket and
// handles CONNECT-IP requests from clients.
func (p *Proxy) ListenAndServe(ctx context.Context) error {
	// Create a QUIC early listener on the shared UDP socket
	ln, err := quic.ListenEarly(p.udpConn, p.tlsConfig, p.quicConfig)
	if err != nil {
		return fmt.Errorf("proxy: failed to listen QUIC: %w", err)
	}

	proxy := &connectip.Proxy{}

	mux := http.NewServeMux()
	mux.HandleFunc("/mion", func(w http.ResponseWriter, r *http.Request) {
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
		// connect-ip-go rejects templates with variables (treats them as
		// IP flow forwarding), so we must use a concrete URL.
		template := uritemplate.MustNew(fmt.Sprintf("https://%s/mion", r.Host))

		// Parse CONNECT-IP request
		req, err := connectip.ParseRequest(r, template)
		if err != nil {
			log.Printf("[proxy] failed to parse CONNECT-IP request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Establish the CONNECT-IP session
		conn, err := proxy.Proxy(w, req)
		if err != nil {
			log.Printf("[proxy] failed to proxy CONNECT-IP: %v", err)
			return
		}

		// Initialize CONNECT-IP session: assign addresses and advertise routes.
		// The client's AllowedIPs become its assigned addresses (what it can send from),
		// and we advertise the overlay prefix as the route (what it can send to).
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
				IPProtocol: 0, // all protocols
			}
			if err := conn.AdvertiseRoute(ctxReq, []connectip.IPRoute{route}); err != nil {
				log.Printf("[proxy] failed to advertise route to peer %s: %v", pr.DisplayID(), err)
				conn.Close()
				return
			}
		}

		// Register connection with the peer.
		// conn is *connectip.Conn (concrete); wrap as TunnelConn before storing.
		// Close any existing session from a previous connect attempt by this peer.
		tc := h3transport.New(conn)
		if old := pr.GetConn(); old != nil {
			_ = old.Close()
		}
		pr.SetConn(tc)
		log.Printf("[proxy] peer %s connected, starting forwarding", pr.DisplayID())

		// Start forwarding from this peer's connection to TUN
		go func() {
			if err := p.ForwardConnToTUN(pr); err != nil {
				log.Printf("[proxy] forwarding for peer %s ended: %v", pr.DisplayID(), err)
			}
		}()
	})

	server := &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}

	log.Printf("[proxy] serving on %s", p.udpConn.LocalAddr())

	// Serve using the early listener
	go func() {
		if err := server.ServeListener(ln); err != nil {
			log.Printf("[proxy] server error: %v", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	server.Close()
	return ctx.Err()
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
