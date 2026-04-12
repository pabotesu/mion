package peer

import (
	"crypto/sha256"
	"net/netip"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"

	"github.com/pabotesu/mion/internal/identity"
)

func makePeerID(s string) identity.PeerID {
	return sha256.Sum256([]byte(s))
}

func TestKnownPeersAddAndLookup(t *testing.T) {
	kp := NewKnownPeers()
	pid := makePeerID("peer1")

	p := &Peer{PeerID: pid}
	if err := kp.Add(p); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	got := kp.Lookup(pid)
	if got == nil {
		t.Fatal("Lookup returned nil")
	}
	if got.PeerID != pid {
		t.Errorf("got PeerID %v, want %v", got.PeerID, pid)
	}
}

func TestKnownPeersDuplicateAdd(t *testing.T) {
	kp := NewKnownPeers()
	pid := makePeerID("peer1")

	p := &Peer{PeerID: pid}
	if err := kp.Add(p); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	if err := kp.Add(p); err == nil {
		t.Fatal("expected error on duplicate Add")
	}
}

func TestKnownPeersRemove(t *testing.T) {
	kp := NewKnownPeers()
	pid := makePeerID("peer1")

	p := &Peer{PeerID: pid}
	kp.Add(p)
	kp.Remove(pid)

	if got := kp.Lookup(pid); got != nil {
		t.Fatal("expected nil after Remove")
	}
	if kp.Len() != 0 {
		t.Errorf("expected Len=0, got %d", kp.Len())
	}
}

func TestKnownPeersAll(t *testing.T) {
	kp := NewKnownPeers()
	pid1 := makePeerID("peer1")
	pid2 := makePeerID("peer2")

	kp.Add(&Peer{PeerID: pid1})
	kp.Add(&Peer{PeerID: pid2})

	all := kp.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(all))
	}
}

func TestKnownPeersLookupUnknown(t *testing.T) {
	kp := NewKnownPeers()
	pid := makePeerID("unknown")

	if got := kp.Lookup(pid); got != nil {
		t.Fatal("expected nil for unknown peer")
	}
}

func TestPeerSetEndpoint(t *testing.T) {
	pid := makePeerID("peer1")
	p := &Peer{PeerID: pid}

	ep := netip.MustParseAddrPort("203.0.113.1:51820")
	if !p.SetEndpoint(ep) {
		t.Fatal("expected SetEndpoint to succeed for dynamic peer")
	}
	if p.Endpoint != ep {
		t.Errorf("Endpoint = %v, want %v", p.Endpoint, ep)
	}
}

func TestPeerSetEndpointConfigured(t *testing.T) {
	pid := makePeerID("peer1")
	p := &Peer{
		PeerID:             pid,
		ConfiguredEndpoint: true,
	}

	ep := netip.MustParseAddrPort("203.0.113.1:51820")
	if p.SetEndpoint(ep) {
		t.Fatal("expected SetEndpoint to fail for configured peer")
	}
}

func TestPeerConnLifecycle(t *testing.T) {
	pid := makePeerID("peer1")
	p := &Peer{PeerID: pid}

	if p.GetConn() != nil {
		t.Fatal("expected nil conn initially")
	}
	if p.Active {
		t.Fatal("expected inactive initially")
	}

	p.SetConn(nil)
	if p.Active {
		t.Fatal("expected inactive after SetConn(nil)")
	}
}

func TestPeerRetryLifecycle(t *testing.T) {
	pid := makePeerID("peer1")
	p := &Peer{PeerID: pid}

	if !p.TryStartRetry() {
		t.Fatal("expected first TryStartRetry to succeed")
	}
	if p.TryStartRetry() {
		t.Fatal("expected second TryStartRetry to fail while retry is active")
	}

	p.StopRetry()
	if !p.TryStartRetry() {
		t.Fatal("expected TryStartRetry to succeed after StopRetry")
	}
}

func TestPeerClearConnIf(t *testing.T) {
	pid := makePeerID("peer1")
	p := &Peer{PeerID: pid}

	conn := &connectip.Conn{}
	p.SetConn(conn)

	if !p.ClearConnIf(conn) {
		t.Fatal("expected ClearConnIf to clear matching connection")
	}
	if p.GetConn() != nil {
		t.Fatal("expected conn to be nil after ClearConnIf")
	}
	if p.Active {
		t.Fatal("expected inactive after ClearConnIf")
	}
}

func TestPeerClearConnIfMismatch(t *testing.T) {
	pid := makePeerID("peer1")
	p := &Peer{PeerID: pid}

	conn := &connectip.Conn{}
	other := &connectip.Conn{}
	p.SetConn(conn)

	if p.ClearConnIf(other) {
		t.Fatal("expected ClearConnIf to be false for non-matching conn")
	}
	if p.GetConn() != conn {
		t.Fatal("expected original conn to remain set")
	}
}
