package ipc

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/peer"
	"github.com/pabotesu/mion/internal/routing"
)

// DeviceState provides the read-only state that the UAPI handler needs
// to respond to "get" requests.
type DeviceState interface {
	PeerID() identity.PeerID
	ListenPort() int
	Peers() *peer.KnownPeers
	AllowedIPs() *routing.AllowedIPs
}

// DeviceMutator provides mutation operations for "set" requests.
type DeviceMutator interface {
	AddPeer(p *peer.Peer) error
	RemovePeer(id identity.PeerID)
	ReconnectPeer(id identity.PeerID) error
}

// Handler processes UAPI connections for a single MION interface.
type Handler struct {
	state   DeviceState
	mutator DeviceMutator
}

// NewHandler creates a UAPI handler.
func NewHandler(state DeviceState, mutator DeviceMutator) *Handler {
	return &Handler{state: state, mutator: mutator}
}

// Serve accepts connections on the UAPIListener and handles them.
// It blocks until the listener is closed.
func (h *Handler) Serve(ln *UAPIListener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed
			return
		}
		go h.handleConn(conn)
	}
}

// handleConn processes a single UAPI connection.
func (h *Handler) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	defer writer.Flush()

	// Read the first line to determine the operation
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)

	switch {
	case line == "get=1":
		h.handleGet(writer)
	case line == "set=1":
		h.handleSet(reader, writer)
	default:
		fmt.Fprintf(writer, "errno=1\n")
	}
}

// handleGet writes the current device and peer state in UAPI format.
// Format follows WireGuard's UAPI: key=value lines, empty line at end.
func (h *Handler) handleGet(w *bufio.Writer) {
	// Device info
	fmt.Fprintf(w, "listen_port=%d\n", h.state.ListenPort())

	// Peer info
	for _, p := range h.state.Peers().All() {
		if len(p.PublicKey) == ed25519.PublicKeySize {
			fmt.Fprintf(w, "public_key=%s\n", base64.StdEncoding.EncodeToString(p.PublicKey))
		}
		fmt.Fprintf(w, "peer_id=%s\n", p.PeerID)

		if p.Endpoint.IsValid() {
			scheme := p.GetEndpointScheme()
			if scheme == "" {
				scheme = "http3"
			}
			fmt.Fprintf(w, "endpoint=%s://%s\n", scheme, p.Endpoint)
		}

		for _, prefix := range p.AllowedIPs {
			fmt.Fprintf(w, "allowed_ip=%s\n", prefix)
		}

		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(w, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}

		if p.Active {
			fmt.Fprintf(w, "active=1\n")
		} else {
			fmt.Fprintf(w, "active=0\n")
		}
	}

	fmt.Fprintf(w, "errno=0\n")
	fmt.Fprintf(w, "\n")
}

// handleSet reads key=value pairs and applies changes.
// Supports adding/removing peers and updating peer configuration.
func (h *Handler) handleSet(r *bufio.Reader, w *bufio.Writer) {
	var currentPeer *peer.Peer
	currentPeerExists := false
	currentPeerModified := false
	currentEndpointChanged := false
	var errResult error

	addedPeers := 0
	removedPeers := 0
	reconnectedPeers := 0
	appliedPeers := 0

	resolvePeerFromPublicKeyField := func(value string) (identity.PeerID, ed25519.PublicKey, error) {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return identity.PeerID{}, nil, fmt.Errorf("invalid public_key")
		}
		pub := ed25519.PublicKey(decoded)

		// Legacy compatibility: public_key historically accepted peer_id strings.
		var direct identity.PeerID
		copy(direct[:], decoded)
		derived := identity.PeerIDFromPublicKey(pub)

		directExists := h.state.Peers().Lookup(direct) != nil
		derivedExists := h.state.Peers().Lookup(derived) != nil

		switch {
		case directExists && !derivedExists:
			return direct, nil, nil
		case derivedExists && !directExists:
			return derived, pub, nil
		case directExists && derivedExists:
			if direct == derived {
				return direct, pub, nil
			}
			return identity.PeerID{}, nil, fmt.Errorf("ambiguous public_key: matches both peer_id and hashed public key")
		default:
			// Default to current semantics: public key input.
			return derived, pub, nil
		}
	}

	flushCurrentPeer := func() {
		if currentPeer == nil {
			return
		}
		if !currentPeerModified {
			currentPeer = nil
			currentPeerExists = false
			currentEndpointChanged = false
			return
		}

		if !currentPeerExists {
			if err := h.mutator.AddPeer(currentPeer); err != nil {
				errResult = err
			} else {
				log.Printf("[uapi] added peer %s", currentPeer.DisplayID())
				addedPeers++
				appliedPeers++
				if currentPeer.Endpoint.IsValid() {
					if err := h.mutator.ReconnectPeer(currentPeer.PeerID); err != nil {
						log.Printf("[uapi] connect trigger for new peer %s failed: %v", currentPeer.DisplayID(), err)
					} else {
						reconnectedPeers++
					}
				}
			}
		} else {
			appliedPeers++
			if currentEndpointChanged {
				log.Printf("[uapi] endpoint changed for peer %s, triggering reconnect", currentPeer.DisplayID())
				if err := h.mutator.ReconnectPeer(currentPeer.PeerID); err != nil {
					log.Printf("[uapi] reconnect trigger failed: %v", err)
				} else {
					reconnectedPeers++
				}
			}
		}

		currentPeer = nil
		currentPeerExists = false
		currentPeerModified = false
		currentEndpointChanged = false
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			errResult = err
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]

		switch key {
		case "public_key", "peer_id":
			flushCurrentPeer()

			// Start a new peer context
			var peerID identity.PeerID
			var pubKey ed25519.PublicKey
			if key == "public_key" {
				id, pub, err := resolvePeerFromPublicKeyField(value)
				if err != nil {
					errResult = err
					continue
				}
				peerID = id
				pubKey = pub
			} else {
				id, err := identity.PeerIDFromBase64(value)
				if err != nil {
					errResult = fmt.Errorf("invalid peer_id: %w", err)
					continue
				}
				peerID = id
			}

			// Check if peer already exists
			existing := h.state.Peers().Lookup(peerID)
			if existing != nil {
				currentPeer = existing
				currentPeerExists = true
				if len(existing.PublicKey) == 0 && len(pubKey) == ed25519.PublicKeySize {
					existing.SetPublicKey(pubKey)
				}
			} else {
				currentPeer = &peer.Peer{PeerID: peerID}
				if len(pubKey) == ed25519.PublicKeySize {
					currentPeer.SetPublicKey(pubKey)
				}
				currentPeerExists = false
			}
			currentPeerModified = false
			currentEndpointChanged = false

		case "remove":
			if currentPeer != nil && value == "true" {
				if h.state.Peers().Lookup(currentPeer.PeerID) != nil {
					h.mutator.RemovePeer(currentPeer.PeerID)
					log.Printf("[uapi] removed peer %s", currentPeer.DisplayID())
					removedPeers++
					appliedPeers++
				}
				currentPeer = nil
				currentPeerExists = false
				currentPeerModified = false
				currentEndpointChanged = false
			}

		case "endpoint":
			if currentPeer == nil {
				continue
			}
			u, err := url.Parse(value)
			if err != nil || u.Host == "" {
				errResult = fmt.Errorf("invalid endpoint %q: use http3://host:port or http2://host:port", value)
				continue
			}
			scheme := strings.ToLower(u.Scheme)
			if scheme != "http3" && scheme != "http2" {
				errResult = fmt.Errorf("invalid endpoint scheme %q: use http3:// or http2://", u.Scheme)
				continue
			}
			host, portStr, err := net.SplitHostPort(u.Host)
			if err != nil {
				errResult = fmt.Errorf("invalid endpoint address %q: %w", u.Host, err)
				continue
			}
			ep, err := netip.ParseAddrPort(net.JoinHostPort(host, portStr))
			if err != nil {
				errResult = fmt.Errorf("invalid endpoint address %q: %w", u.Host, err)
				continue
			}
			if currentPeer.Endpoint != ep || currentPeer.GetEndpointScheme() != scheme {
				currentEndpointChanged = true
			}
			currentPeer.Endpoint = ep
			currentPeer.SetEndpointScheme(scheme)
			currentPeer.ConfiguredEndpoint = true
			currentPeerModified = true

		case "allowed_ip":
			if currentPeer == nil {
				continue
			}
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				errResult = fmt.Errorf("invalid allowed_ip: %w", err)
				continue
			}
			currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, prefix)
			currentPeerModified = true

		case "persistent_keepalive_interval":
			if currentPeer == nil {
				continue
			}
			secs, err := strconv.Atoi(value)
			if err != nil {
				errResult = fmt.Errorf("invalid persistent_keepalive_interval: %w", err)
				continue
			}
			currentPeer.PersistentKeepalive = secs
			currentPeerModified = true
		}
	}

	flushCurrentPeer()

	if errResult != nil {
		log.Printf("[uapi] set error: %v", errResult)
		fmt.Fprintf(w, "status=error\n")
		fmt.Fprintf(w, "error=%s\n", errResult.Error())
		fmt.Fprintf(w, "errno=1\n")
	} else {
		fmt.Fprintf(w, "status=ok\n")
		fmt.Fprintf(w, "applied_peers=%d\n", appliedPeers)
		fmt.Fprintf(w, "added_peers=%d\n", addedPeers)
		fmt.Fprintf(w, "removed_peers=%d\n", removedPeers)
		fmt.Fprintf(w, "reconnected_peers=%d\n", reconnectedPeers)
		fmt.Fprintf(w, "errno=0\n")
	}
	fmt.Fprintf(w, "\n")
}
