// Package client implements the MION client logic.
// The client dials one or more proxies via CONNECT-IP over a single UDP socket.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/pabotesu/mion/internal/peer"
	"github.com/pabotesu/mion/internal/routing"
	"github.com/pabotesu/mion/internal/tunnel"
)

// Client manages outbound CONNECT-IP sessions to proxy peers.
type Client struct {
	udpConn    *net.UDPConn
	peers      *peer.KnownPeers
	allowedIPs *routing.AllowedIPs
	tun        tunnel.Device
	tlsConfig  *tls.Config
	quicConfig *quic.Config
}

// NewClient creates a new client that uses the provided shared UDP socket.
func NewClient(udpConn *net.UDPConn, peers *peer.KnownPeers, allowedIPs *routing.AllowedIPs, tun tunnel.Device, tlsConfig *tls.Config) *Client {
	return &Client{
		udpConn:    udpConn,
		peers:      peers,
		allowedIPs: allowedIPs,
		tun:        tun,
		tlsConfig:  tlsConfig,
		quicConfig: &quic.Config{
			EnableDatagrams: true,
			KeepAlivePeriod: 25 * time.Second,
		},
	}
}

// DialPeer establishes a CONNECT-IP session with a single peer (proxy).
// All dials go through the shared udpConn (same socket requirement).
func (c *Client) DialPeer(ctx context.Context, p *peer.Peer) error {
	if !p.Endpoint.IsValid() {
		return fmt.Errorf("client: peer %s has no endpoint configured", p.PeerID)
	}

	addr := &net.UDPAddr{
		IP:   p.Endpoint.Addr().AsSlice(),
		Port: int(p.Endpoint.Port()),
	}

	qconn, err := quic.Dial(ctx, c.udpConn, addr, c.tlsConfig, c.quicConfig)
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
		return fmt.Errorf("client: CONNECT-IP dial to %s failed: %w", p.PeerID, err)
	}

	// Wait for the proxy to send address assignment and route advertisement.
	// This ensures the CONNECT-IP session is fully initialized before forwarding.
	if _, err := ipconn.LocalPrefixes(ctx); err != nil {
		log.Printf("[client] warning: failed to receive address assignment from %s: %v", p.PeerID, err)
	}
	if _, err := ipconn.Routes(ctx); err != nil {
		log.Printf("[client] warning: failed to receive routes from %s: %v", p.PeerID, err)
	}

	p.SetConn(ipconn)
	log.Printf("[client] connected to peer %s at %s", p.PeerID, p.Endpoint)

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
			log.Printf("[client] peer %s not yet reachable, will retry in background", p.PeerID)
			go c.RetryDial(ctx, p)
			continue
		}
		p.SetActive(true)
		go func(pr *peer.Peer) {
			if err := c.ForwardConnToTUN(pr); err != nil {
				log.Printf("[client] peer %s disconnected, will retry", pr.PeerID)
				c.RetryDial(ctx, pr)
			}
		}(p)
	}
	return nil
}

// RetryDial retries dialing a peer with exponential backoff until success or context cancellation.
// When connected, it blocks on ForwardConnToTUN; if that ends, it loops back to retry.
func (c *Client) RetryDial(ctx context.Context, p *peer.Peer) {
	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		log.Printf("[client] dialing peer %s at %s ...", p.PeerID, p.Endpoint)
		if err := c.DialPeer(ctx, p); err != nil {
			log.Printf("[client] peer %s unreachable, next attempt in %s", p.PeerID, backoff*2)
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		p.SetActive(true)
		// Block on forwarding; if it ends, the peer went away — loop back to retry
		if err := c.ForwardConnToTUN(p); err != nil {
			log.Printf("[client] peer %s disconnected, will retry", p.PeerID)
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

		if _, err := conn.WritePacket(pkt); err != nil {
			log.Printf("[client] write to peer %s failed: %v", p.PeerID, err)
		}
	}
}

// ForwardConnToTUN reads packets from a peer's CONNECT-IP connection and writes to TUN.
func (c *Client) ForwardConnToTUN(p *peer.Peer) error {
	conn := p.GetConn()
	if conn == nil {
		return fmt.Errorf("client: peer %s has no connection", p.PeerID)
	}

	buf := make([]byte, c.tun.MTU())
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil {
			p.SetConn(nil)
			p.SetActive(false)
			return fmt.Errorf("client: read from peer %s failed: %w", p.PeerID, err)
		}
		pkt := buf[:n]

		// Update last receive timestamp for keepalive/failover tracking
		p.UpdateLastReceive()

		srcIP := extractSrcIP(pkt)
		if !c.allowedIPs.ValidateSource(srcIP, p.PeerID) {
			log.Printf("[client] dropping packet from peer %s: src %s not in AllowedIPs", p.PeerID, srcIP)
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
