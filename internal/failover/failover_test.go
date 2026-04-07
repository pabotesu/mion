package failover

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/peer"
)

func makePeerID(s string) identity.PeerID {
	return sha256.Sum256([]byte(s))
}

func TestFailoverTriggersReconnect(t *testing.T) {
	peers := peer.NewKnownPeers()
	pid := makePeerID("peer1")
	p := &peer.Peer{
		PeerID:             pid,
		Endpoint:           netip.MustParseAddrPort("203.0.113.1:51820"),
		ConfiguredEndpoint: false,
		Active:             true, // marked active
		Conn:               nil,  // but connection is gone
		EndpointCandidates: []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.1:51820"),
			netip.MustParseAddrPort("192.0.2.1:51820"),
		},
	}
	peers.Add(p)

	var reconnected atomic.Int32
	reconnectFn := func(ctx context.Context, pr *peer.Peer) error {
		reconnected.Add(1)
		return nil
	}

	mgr := NewManager(peers, reconnectFn, 30*time.Second)

	ctx := context.Background()
	mgr.check(ctx)

	// Give the goroutine time to execute
	time.Sleep(50 * time.Millisecond)

	if reconnected.Load() != 1 {
		t.Errorf("expected 1 reconnect attempt, got %d", reconnected.Load())
	}

	// Endpoint should have rotated to the first candidate
	if p.Endpoint != netip.MustParseAddrPort("198.51.100.1:51820") {
		t.Errorf("expected endpoint to rotate, got %v", p.Endpoint)
	}
}

func TestFailoverNoCandidates(t *testing.T) {
	peers := peer.NewKnownPeers()
	pid := makePeerID("peer1")
	p := &peer.Peer{
		PeerID:             pid,
		Endpoint:           netip.MustParseAddrPort("203.0.113.1:51820"),
		ConfiguredEndpoint: false,
		Active:             true, // marked active
		Conn:               nil,  // but connection is gone
	}
	peers.Add(p)

	var reconnected atomic.Int32
	reconnectFn := func(ctx context.Context, pr *peer.Peer) error {
		reconnected.Add(1)
		return nil
	}

	mgr := NewManager(peers, reconnectFn, 30*time.Second)

	ctx := context.Background()
	mgr.check(ctx)
	time.Sleep(50 * time.Millisecond)

	if reconnected.Load() != 1 {
		t.Errorf("expected 1 reconnect attempt, got %d", reconnected.Load())
	}

	// Endpoint should remain the same (no candidates)
	if p.Endpoint != netip.MustParseAddrPort("203.0.113.1:51820") {
		t.Errorf("expected endpoint unchanged, got %v", p.Endpoint)
	}
}

func TestFailoverSkipsHealthyPeers(t *testing.T) {
	peers := peer.NewKnownPeers()
	pid := makePeerID("peer1")
	p := &peer.Peer{
		PeerID:             pid,
		Endpoint:           netip.MustParseAddrPort("203.0.113.1:51820"),
		ConfiguredEndpoint: false,
		Active:             false, // inactive peer — should be skipped
	}
	peers.Add(p)

	var reconnected atomic.Int32
	reconnectFn := func(ctx context.Context, pr *peer.Peer) error {
		reconnected.Add(1)
		return nil
	}

	mgr := NewManager(peers, reconnectFn, 30*time.Second)
	ctx := context.Background()
	mgr.check(ctx)
	time.Sleep(50 * time.Millisecond)

	if reconnected.Load() != 0 {
		t.Errorf("expected 0 reconnect attempts for inactive peer, got %d", reconnected.Load())
	}
}

func TestNextEndpointCandidateRotation(t *testing.T) {
	p := &peer.Peer{
		PeerID: makePeerID("peer1"),
		EndpointCandidates: []netip.AddrPort{
			netip.MustParseAddrPort("1.1.1.1:1"),
			netip.MustParseAddrPort("2.2.2.2:2"),
			netip.MustParseAddrPort("3.3.3.3:3"),
		},
	}

	got1 := p.NextEndpointCandidate()
	if got1 != netip.MustParseAddrPort("1.1.1.1:1") {
		t.Errorf("first = %v", got1)
	}

	got2 := p.NextEndpointCandidate()
	if got2 != netip.MustParseAddrPort("2.2.2.2:2") {
		t.Errorf("second = %v", got2)
	}

	got3 := p.NextEndpointCandidate()
	if got3 != netip.MustParseAddrPort("3.3.3.3:3") {
		t.Errorf("third = %v", got3)
	}

	// Should cycle back to first
	got4 := p.NextEndpointCandidate()
	if got4 != netip.MustParseAddrPort("1.1.1.1:1") {
		t.Errorf("fourth (cycle) = %v", got4)
	}
}
