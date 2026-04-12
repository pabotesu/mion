package ipc

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
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
		// public_key is the peer_id in base64
		fmt.Fprintf(w, "public_key=%s\n", base64.StdEncoding.EncodeToString(p.PeerID[:]))

		if p.Endpoint.IsValid() {
			fmt.Fprintf(w, "endpoint=%s\n", p.Endpoint)
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
				log.Printf("[uapi] added peer %s", currentPeer.PeerID)
				addedPeers++
				appliedPeers++
			}
		} else {
			appliedPeers++
			if currentEndpointChanged {
				log.Printf("[uapi] endpoint changed for peer %s, triggering reconnect", currentPeer.PeerID)
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
		case "public_key":
			flushCurrentPeer()

			// Start a new peer context
			peerIDBytes, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(peerIDBytes) != 32 {
				errResult = fmt.Errorf("invalid public_key")
				continue
			}
			var peerID identity.PeerID
			copy(peerID[:], peerIDBytes)

			// Check if peer already exists
			existing := h.state.Peers().Lookup(peerID)
			if existing != nil {
				currentPeer = existing
				currentPeerExists = true
			} else {
				currentPeer = &peer.Peer{PeerID: peerID}
				currentPeerExists = false
			}
			currentPeerModified = false
			currentEndpointChanged = false

		case "remove":
			if currentPeer != nil && value == "true" {
				if h.state.Peers().Lookup(currentPeer.PeerID) != nil {
					h.mutator.RemovePeer(currentPeer.PeerID)
					log.Printf("[uapi] removed peer %s", currentPeer.PeerID)
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
			ep, err := netip.ParseAddrPort(value)
			if err != nil {
				errResult = fmt.Errorf("invalid endpoint: %w", err)
				continue
			}
			if currentPeer.Endpoint != ep {
				currentEndpointChanged = true
			}
			currentPeer.Endpoint = ep
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
