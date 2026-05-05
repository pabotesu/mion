// Package client implements the MION client logic.
// The client dials one or more proxies via CONNECT-IP over a single UDP socket.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"

	"github.com/pabotesu/mion/internal/routing"
	h2transport "github.com/pabotesu/mion/internal/transport/h2"
	h3transport "github.com/pabotesu/mion/internal/transport/h3"
	"github.com/pabotesu/mion/peer"
	"github.com/pabotesu/mion/internal/tunnel"
)

// Client manages outbound CONNECT-IP sessions to proxy peers.
type Client struct {
	udpConn    *net.UDPConn
	transport  *quic.Transport
	peers      *peer.KnownPeers
	allowedIPs *routing.AllowedIPs
	tun        tunnel.Device
	tlsConfig  *tls.Config
	quicConfig *quic.Config
}

// NewClient creates a new client that uses the provided shared UDP socket.
func NewClient(udpConn *net.UDPConn, peers *peer.KnownPeers, allowedIPs *routing.AllowedIPs, tun tunnel.Device, tlsConfig *tls.Config) *Client {
	// Clone TLS config and enable session resumption for QUIC 0-RTT reconnects.
	tlsCfg := tlsConfig.Clone()
	tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)
	return &Client{
		udpConn:    udpConn,
		transport:  &quic.Transport{Conn: udpConn},
		peers:      peers,
		allowedIPs: allowedIPs,
		tun:        tun,
		tlsConfig:  tlsCfg,
		quicConfig: &quic.Config{
			EnableDatagrams: true,
			KeepAlivePeriod: 10 * time.Second,
			MaxIdleTimeout:  15 * time.Second,
		},
	}
}

// DialPeer establishes a CONNECT-IP session with a single peer (proxy).
// The transport protocol is selected by p.EndpointScheme ("http3" or "http2").
func (c *Client) DialPeer(ctx context.Context, p *peer.Peer) error {
	if !p.Endpoint.IsValid() {
		return fmt.Errorf("client: peer %s has no endpoint configured", p.DisplayID())
	}

	switch p.GetEndpointScheme() {
	case "http3", "": // "" = legacy fallback
		return c.dialH3(ctx, p)
	case "http2":
		return c.dialH2(ctx, p)
	default:
		return fmt.Errorf("client: unknown endpoint scheme %q for peer %s", p.GetEndpointScheme(), p.DisplayID())
	}
}

// dialH3 establishes an HTTP/3 CONNECT-IP session with a peer.
func (c *Client) dialH3(ctx context.Context, p *peer.Peer) error {
	addr := &net.UDPAddr{
		IP:   p.Endpoint.Addr().AsSlice(),
		Port: int(p.Endpoint.Port()),
	}

	qconn, err := c.transport.Dial(ctx, addr, c.tlsConfig, c.quicConfig)
	if err != nil {
		return fmt.Errorf("client: QUIC dial to %s failed: %w", p.Endpoint, err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(qconn)

	// Build authority suitable for URL: IPv6 needs brackets (e.g. [::1]:1234)
	var authority string
	if p.Endpoint.Addr().Is6() {
		authority = fmt.Sprintf("[%s]:%d", p.Endpoint.Addr(), p.Endpoint.Port())
	} else {
		authority = p.Endpoint.String()
	}

	template := uritemplate.MustNew(
		fmt.Sprintf("https://%s/mion", authority),
	)

	ipconn, _, err := connectip.Dial(ctx, hconn, template)
	if err != nil {
		return fmt.Errorf("client: CONNECT-IP dial to %s failed: %w", p.DisplayID(), err)
	}

	// Wait for the proxy to send address assignment and route advertisement.
	// This ensures the CONNECT-IP session is fully initialized before forwarding.
	if _, err := ipconn.LocalPrefixes(ctx); err != nil {
		log.Printf("[client] warning: failed to receive address assignment from %s: %v", p.DisplayID(), err)
	}
	if _, err := ipconn.Routes(ctx); err != nil {
		log.Printf("[client] warning: failed to receive routes from %s: %v", p.DisplayID(), err)
	}

	p.SetConn(h3transport.New(ipconn))
	log.Printf("[client] connected to peer %s at %s (http3)", p.DisplayID(), p.Endpoint)

	return nil
}

// dialH2 establishes an HTTP/2 bidirectional tunnel to a peer.
// IP packets are framed as capsules over an HTTP/2 POST request / response body pair.
func (c *Client) dialH2(ctx context.Context, p *peer.Peer) error {
	// Build the target URL.
	var rawURL string
	if p.Endpoint.Addr().Is6() {
		rawURL = fmt.Sprintf("https://[%s]:%d/mion", p.Endpoint.Addr(), p.Endpoint.Port())
	} else {
		rawURL = fmt.Sprintf("https://%s/mion", p.Endpoint)
	}

	// Clone the TLS config and restrict to HTTP/2 ALPN.
	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}

	// Use golang.org/x/net/http2.Transport to force HTTP/2 (avoids fallback to HTTP/1.1).
	tr := &http2.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{Transport: tr}

	// io.Pipe: pw is written by WritePacket (client→server), pr is the request body.
	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fmt.Errorf("client[h2]: build request: %w", err)
	}
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/octet-stream")

	// Do sends HEADERS immediately; returns when the server's 200 HEADERS arrive.
	resp, err := httpClient.Do(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fmt.Errorf("client[h2]: POST to %s failed: %w", p.DisplayID(), err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pr.Close()
		_ = pw.Close()
		_ = resp.Body.Close()
		return fmt.Errorf("client[h2]: server responded with %d", resp.StatusCode)
	}

	conn := h2transport.NewClientConn(pw, resp.Body)
	p.SetConn(conn)
	log.Printf("[client] connected to peer %s at %s (http2)", p.DisplayID(), p.Endpoint)
	return nil
}

// DialAllPeers dials all peers that have a configured endpoint.
// For each successfully connected peer, it starts a ForwardConnToTUN goroutine.
// Peers that fail to connect are retried in the background with exponential backoff.
func (c *Client) DialAllPeers(ctx context.Context) error {
	for _, p := range c.peers.All() {
		if !p.Endpoint.IsValid() {
			continue
		}
		if err := c.DialPeer(ctx, p); err != nil {
			log.Printf("[client] peer %s not yet reachable, will retry in background", p.DisplayID())
			c.StartRetry(ctx, p)
			continue
		}
		p.SetActive(true)
		go func(pr *peer.Peer) {
			if err := c.ForwardConnToTUN(pr); err != nil {
				log.Printf("[client] peer %s disconnected, will retry", pr.DisplayID())
				c.StartRetry(ctx, pr)
			}
		}(p)
	}
	return nil
}

// StartRetry starts a background retry loop for a peer if one is not already running.
func (c *Client) StartRetry(ctx context.Context, p *peer.Peer) {
	if !p.TryStartRetry() {
		return
	}
	go c.RetryDial(ctx, p)
}

// RetryDial retries dialing a peer with exponential backoff until success or context cancellation.
// When connected, it blocks on ForwardConnToTUN; if that ends, it loops back to retry.
func (c *Client) RetryDial(ctx context.Context, p *peer.Peer) {
	defer p.StopRetry()

	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second

	for {
		if p.GetConn() != nil {
			return
		}

		nextAttempt := backoff
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextAttempt):
		}

		if ctx.Err() != nil {
			return
		}

		log.Printf("[client] dialing peer %s at %s ...", p.DisplayID(), p.Endpoint)
		if err := c.DialPeer(ctx, p); err != nil {
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			log.Printf("[client] peer %s unreachable, next attempt in %s", p.DisplayID(), backoff)
			continue
		}

		p.SetActive(true)
		// Block on forwarding; if it ends, the peer went away — loop back to retry
		if err := c.ForwardConnToTUN(p); err != nil {
			log.Printf("[client] peer %s disconnected, will retry", p.DisplayID())
		}
		backoff = 2 * time.Second // reset backoff for next retry
	}
}

// ForwardTUNToConn reads packets from TUN, looks up the destination peer via
// AllowedIPs, and writes to the corresponding CONNECT-IP connection.
func (c *Client) ForwardTUNToConn(ctx context.Context) error {
	buf := make([]byte, c.tun.MTU())
	for {
		n, err := c.tun.Read(buf)
		if err != nil {
			return fmt.Errorf("client: TUN read error: %w", err)
		}
		pkt := buf[:n]

		dstIP := extractDstIP(pkt)
		if !dstIP.IsValid() {
			continue
		}

		peerID, ok := c.allowedIPs.Lookup(dstIP)
		if !ok {
			continue // no route
		}

		p := c.peers.Lookup(peerID)
		if p == nil {
			continue
		}

		conn := p.GetConn()
		if conn == nil {
			continue // peer not connected
		}

		if err := conn.WritePacket(pkt); err != nil {
			log.Printf("[client] write to peer %s failed: %v", p.DisplayID(), err)
			// A WritePacket error means the session is broken (not a silent drop).
			// ClearConnIf ensures ForwardConnToTUN detects the breakage and
			// triggers reconnection via StartRetry.
			p.ClearConnIf(conn)
		}
	}
}

// ForwardConnToTUN reads packets from a peer's CONNECT-IP connection and writes to TUN.
func (c *Client) ForwardConnToTUN(p *peer.Peer) error {
	conn := p.GetConn()
	if conn == nil {
		return fmt.Errorf("client: peer %s has no connection", p.DisplayID())
	}

	buf := make([]byte, c.tun.MTU())
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil {
			p.ClearConnIf(conn)
			return fmt.Errorf("client: read from peer %s failed: %w", p.DisplayID(), err)
		}
		// n==0 means a keepalive pong capsule from proxy; update liveness timestamp.
		if n == 0 {
			p.UpdateLastReceive()
			continue
		}
		pkt := buf[:n]

		// Update last receive timestamp for keepalive/failover tracking
		p.UpdateLastReceive()

		srcIP := extractSrcIP(pkt)
		if !c.allowedIPs.ValidateSource(srcIP, p.PeerID) {
			log.Printf("[client] dropping packet from peer %s: src %s not in AllowedIPs", p.DisplayID(), srcIP)
			continue
		}

		if _, err := c.tun.Write(pkt); err != nil {
			log.Printf("[client] TUN write error: %v", err)
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
