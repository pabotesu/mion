package ipc

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/peer"
	"github.com/pabotesu/mion/internal/routing"
)

type mockState struct {
	peerID     identity.PeerID
	listenPort int
	peers      *peer.KnownPeers
	allowedIPs *routing.AllowedIPs
}

func (m *mockState) PeerID() identity.PeerID         { return m.peerID }
func (m *mockState) ListenPort() int                 { return m.listenPort }
func (m *mockState) Peers() *peer.KnownPeers         { return m.peers }
func (m *mockState) AllowedIPs() *routing.AllowedIPs { return m.allowedIPs }

type mockMutator struct {
	state          *mockState
	reconnectCalls []identity.PeerID
}

func (m *mockMutator) AddPeer(p *peer.Peer) error {
	if err := m.state.peers.Add(p); err != nil {
		return err
	}
	for _, prefix := range p.AllowedIPs {
		m.state.allowedIPs.Insert(prefix, p.PeerID)
	}
	return nil
}

func (m *mockMutator) RemovePeer(id identity.PeerID) {
	m.state.allowedIPs.Remove(id)
	m.state.peers.Remove(id)
}

func (m *mockMutator) ReconnectPeer(id identity.PeerID) error {
	m.reconnectCalls = append(m.reconnectCalls, id)
	return nil
}

func makePeerID(s string) identity.PeerID {
	return sha256.Sum256([]byte(s))
}

func newTestHandler() (*Handler, *mockState, *mockMutator) {
	st := &mockState{
		peerID:     makePeerID("self"),
		listenPort: 51820,
		peers:      peer.NewKnownPeers(),
		allowedIPs: routing.NewAllowedIPs(),
	}
	mut := &mockMutator{state: st}
	return NewHandler(st, mut), st, mut
}

func TestHandleGetEmpty(t *testing.T) {
	h, _, _ := newTestHandler()

	var buf strings.Builder
	w := bufio.NewWriter(&buf)
	h.handleGet(w)
	w.Flush()

	output := buf.String()
	if !strings.Contains(output, "listen_port=51820") {
		t.Errorf("expected listen_port=51820, got:\n%s", output)
	}
	if !strings.Contains(output, "errno=0") {
		t.Errorf("expected errno=0, got:\n%s", output)
	}
}

func TestHandleGetWithPeers(t *testing.T) {
	h, st, _ := newTestHandler()

	pid := makePeerID("peer1")
	p := &peer.Peer{
		PeerID:              pid,
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		Endpoint:            netip.MustParseAddrPort("203.0.113.1:51820"),
		ConfiguredEndpoint:  true,
		PersistentKeepalive: 25,
		Active:              false,
	}
	st.peers.Add(p)

	var buf strings.Builder
	w := bufio.NewWriter(&buf)
	h.handleGet(w)
	w.Flush()

	output := buf.String()
	pidB64 := base64.StdEncoding.EncodeToString(pid[:])
	if !strings.Contains(output, "public_key="+pidB64) {
		t.Errorf("expected public_key in output, got:\n%s", output)
	}
	if !strings.Contains(output, "endpoint=203.0.113.1:51820") {
		t.Errorf("expected endpoint in output, got:\n%s", output)
	}
	if !strings.Contains(output, "allowed_ip=10.0.0.0/24") {
		t.Errorf("expected allowed_ip in output, got:\n%s", output)
	}
	if !strings.Contains(output, "persistent_keepalive_interval=25") {
		t.Errorf("expected persistent_keepalive in output, got:\n%s", output)
	}
	if !strings.Contains(output, "active=0") {
		t.Errorf("expected active=0 in output, got:\n%s", output)
	}
}

func TestHandleSetAddPeer(t *testing.T) {
	h, st, mut := newTestHandler()

	pid := makePeerID("newpeer")
	pidB64 := base64.StdEncoding.EncodeToString(pid[:])

	input := fmt.Sprintf("public_key=%s\nendpoint=203.0.113.2:51820\nallowed_ip=10.0.1.0/24\npersistent_keepalive_interval=30\n\n", pidB64)
	r := bufio.NewReader(strings.NewReader(input))
	var buf strings.Builder
	w := bufio.NewWriter(&buf)

	h.handleSet(r, w)
	w.Flush()

	output := buf.String()
	if !strings.Contains(output, "errno=0") {
		t.Errorf("expected errno=0, got:\n%s", output)
	}
	if !strings.Contains(output, "status=ok") {
		t.Errorf("expected status=ok, got:\n%s", output)
	}
	if !strings.Contains(output, "added_peers=1") {
		t.Errorf("expected added_peers=1, got:\n%s", output)
	}
	if !strings.Contains(output, "reconnected_peers=1") {
		t.Errorf("expected reconnected_peers=1, got:\n%s", output)
	}

	p := st.peers.Lookup(pid)
	if p == nil {
		t.Fatal("expected peer to be added")
	}
	if p.Endpoint != netip.MustParseAddrPort("203.0.113.2:51820") {
		t.Errorf("Endpoint = %v", p.Endpoint)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != netip.MustParsePrefix("10.0.1.0/24") {
		t.Errorf("AllowedIPs = %v", p.AllowedIPs)
	}
	if p.PersistentKeepalive != 30 {
		t.Errorf("PersistentKeepalive = %d", p.PersistentKeepalive)
	}
	if len(mut.reconnectCalls) != 1 || mut.reconnectCalls[0] != pid {
		t.Errorf("expected reconnect to be called once for new peer, got %v", mut.reconnectCalls)
	}
}

func TestHandleSetMultiPeerAdd(t *testing.T) {
	h, st, _ := newTestHandler()

	pid1 := makePeerID("multi-peer-1")
	pid2 := makePeerID("multi-peer-2")
	pid1B64 := base64.StdEncoding.EncodeToString(pid1[:])
	pid2B64 := base64.StdEncoding.EncodeToString(pid2[:])

	input := fmt.Sprintf(
		"public_key=%s\nendpoint=203.0.113.10:51820\nallowed_ip=10.10.0.1/32\npublic_key=%s\nendpoint=203.0.113.11:51820\nallowed_ip=10.10.0.2/32\n\n",
		pid1B64,
		pid2B64,
	)
	r := bufio.NewReader(strings.NewReader(input))
	var buf strings.Builder
	w := bufio.NewWriter(&buf)

	h.handleSet(r, w)
	w.Flush()

	output := buf.String()
	if !strings.Contains(output, "errno=0") {
		t.Errorf("expected errno=0, got:\n%s", output)
	}
	if !strings.Contains(output, "added_peers=2") {
		t.Errorf("expected added_peers=2, got:\n%s", output)
	}

	if st.peers.Lookup(pid1) == nil {
		t.Fatal("expected first peer to be added")
	}
	if st.peers.Lookup(pid2) == nil {
		t.Fatal("expected second peer to be added")
	}
}

func TestHandleSetRemovePeer(t *testing.T) {
	h, st, _ := newTestHandler()

	pid := makePeerID("existing")
	st.peers.Add(&peer.Peer{
		PeerID:     pid,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	st.allowedIPs.Insert(netip.MustParsePrefix("10.0.0.0/24"), pid)

	pidB64 := base64.StdEncoding.EncodeToString(pid[:])
	input := fmt.Sprintf("public_key=%s\nremove=true\n\n", pidB64)
	r := bufio.NewReader(strings.NewReader(input))
	var buf strings.Builder
	w := bufio.NewWriter(&buf)

	h.handleSet(r, w)
	w.Flush()

	if !strings.Contains(buf.String(), "errno=0") {
		t.Errorf("expected errno=0, got:\n%s", buf.String())
	}

	if st.peers.Lookup(pid) != nil {
		t.Error("expected peer to be removed")
	}
}

func TestHandleConnGet(t *testing.T) {
	h, _, _ := newTestHandler()

	clientConn, serverConn := net.Pipe()

	go func() {
		h.handleConn(serverConn)
	}()

	fmt.Fprint(clientConn, "get=1\n")

	scanner := bufio.NewScanner(clientConn)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if line == "" {
			break
		}
	}
	clientConn.Close()

	result := strings.Join(lines, "\n")
	if !strings.Contains(result, "listen_port=51820") {
		t.Errorf("expected listen_port in response, got:\n%s", result)
	}
	if !strings.Contains(result, "errno=0") {
		t.Errorf("expected errno=0 in response, got:\n%s", result)
	}
}
