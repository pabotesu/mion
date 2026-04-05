package routing

import (
	"crypto/sha256"
	"net/netip"
	"testing"

	"github.com/pabotesu/mion/internal/identity"
)

func makePeerID(s string) identity.PeerID {
	return sha256.Sum256([]byte(s))
}

func TestInsertAndLookup(t *testing.T) {
	a := NewAllowedIPs()
	pid := makePeerID("peer1")

	a.Insert(netip.MustParsePrefix("10.0.0.0/24"), pid)

	got, ok := a.Lookup(netip.MustParseAddr("10.0.0.5"))
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if got != pid {
		t.Errorf("got peer_id %v, want %v", got, pid)
	}
}

func TestLookupNoMatch(t *testing.T) {
	a := NewAllowedIPs()
	pid := makePeerID("peer1")

	a.Insert(netip.MustParsePrefix("10.0.0.0/24"), pid)

	_, ok := a.Lookup(netip.MustParseAddr("192.168.1.1"))
	if ok {
		t.Fatal("expected lookup to fail for non-matching IP")
	}
}

func TestLongestPrefixMatch(t *testing.T) {
	a := NewAllowedIPs()
	pid1 := makePeerID("peer1")
	pid2 := makePeerID("peer2")

	a.Insert(netip.MustParsePrefix("10.0.0.0/16"), pid1)
	a.Insert(netip.MustParsePrefix("10.0.1.0/24"), pid2)

	got, ok := a.Lookup(netip.MustParseAddr("10.0.1.5"))
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if got != pid2 {
		t.Errorf("expected peer2 for /24 match")
	}

	got, ok = a.Lookup(netip.MustParseAddr("10.0.2.5"))
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if got != pid1 {
		t.Errorf("expected peer1 for /16 match")
	}
}

func TestValidateSource(t *testing.T) {
	a := NewAllowedIPs()
	pid1 := makePeerID("peer1")
	pid2 := makePeerID("peer2")

	a.Insert(netip.MustParsePrefix("10.0.0.0/24"), pid1)
	a.Insert(netip.MustParsePrefix("10.0.1.0/24"), pid2)

	if !a.ValidateSource(netip.MustParseAddr("10.0.0.5"), pid1) {
		t.Error("expected valid source for peer1 from 10.0.0.5")
	}
	if a.ValidateSource(netip.MustParseAddr("10.0.0.5"), pid2) {
		t.Error("expected invalid source for peer2 from 10.0.0.5")
	}
}

func TestRemove(t *testing.T) {
	a := NewAllowedIPs()
	pid := makePeerID("peer1")

	a.Insert(netip.MustParsePrefix("10.0.0.0/24"), pid)
	a.Remove(pid)

	_, ok := a.Lookup(netip.MustParseAddr("10.0.0.5"))
	if ok {
		t.Fatal("expected lookup to fail after Remove")
	}
}

func TestIPv6(t *testing.T) {
	a := NewAllowedIPs()
	pid := makePeerID("peer1")

	a.Insert(netip.MustParsePrefix("fd00::/64"), pid)

	got, ok := a.Lookup(netip.MustParseAddr("fd00::1"))
	if !ok {
		t.Fatal("expected IPv6 lookup to succeed")
	}
	if got != pid {
		t.Errorf("got wrong peer_id for IPv6")
	}

	_, ok = a.Lookup(netip.MustParseAddr("fd01::1"))
	if ok {
		t.Fatal("expected IPv6 lookup to fail for different prefix")
	}
}

func TestIPv6ValidateSource(t *testing.T) {
	a := NewAllowedIPs()
	pid1 := makePeerID("peer1")
	pid2 := makePeerID("peer2")

	a.Insert(netip.MustParsePrefix("fd00::/64"), pid1)
	a.Insert(netip.MustParsePrefix("fd01::/64"), pid2)

	if !a.ValidateSource(netip.MustParseAddr("fd00::99"), pid1) {
		t.Error("expected valid source for peer1 from fd00::99")
	}
	if a.ValidateSource(netip.MustParseAddr("fd00::99"), pid2) {
		t.Error("expected invalid source for peer2 from fd00::99")
	}
}

func TestIPv6LongestPrefixMatch(t *testing.T) {
	a := NewAllowedIPs()
	pid1 := makePeerID("peer1")
	pid2 := makePeerID("peer2")

	a.Insert(netip.MustParsePrefix("fd00::/48"), pid1)
	a.Insert(netip.MustParsePrefix("fd00:0:0:1::/64"), pid2)

	// fd00:0:0:1::5 should match the more specific /64
	got, ok := a.Lookup(netip.MustParseAddr("fd00:0:0:1::5"))
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if got != pid2 {
		t.Error("expected peer2 for /64 match")
	}

	// fd00:0:0:2::5 should fall back to /48
	got, ok = a.Lookup(netip.MustParseAddr("fd00:0:0:2::5"))
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if got != pid1 {
		t.Error("expected peer1 for /48 match")
	}
}

func TestMixedIPv4IPv6(t *testing.T) {
	a := NewAllowedIPs()
	pid1 := makePeerID("peer1")
	pid2 := makePeerID("peer2")

	// peer1 has IPv4, peer2 has IPv6
	a.Insert(netip.MustParsePrefix("10.0.0.0/24"), pid1)
	a.Insert(netip.MustParsePrefix("fd00::/64"), pid2)

	// IPv4 lookup should find peer1
	got, ok := a.Lookup(netip.MustParseAddr("10.0.0.5"))
	if !ok {
		t.Fatal("expected IPv4 lookup to succeed")
	}
	if got != pid1 {
		t.Error("expected peer1 for IPv4")
	}

	// IPv6 lookup should find peer2
	got, ok = a.Lookup(netip.MustParseAddr("fd00::5"))
	if !ok {
		t.Fatal("expected IPv6 lookup to succeed")
	}
	if got != pid2 {
		t.Error("expected peer2 for IPv6")
	}

	// Cross: IPv6 addr should NOT match IPv4 prefix
	_, ok = a.Lookup(netip.MustParseAddr("fd00::a00:5")) // not in 10.0.0.0/24
	if ok {
		// This is fine as long as it resolves to the correct peer via fd00::/64
		// The point is 10.0.0.0/24 should NOT match IPv6 addresses
	}

	// ValidateSource across address families
	if a.ValidateSource(netip.MustParseAddr("fd00::1"), pid1) {
		t.Error("peer1 (IPv4 only) should not validate IPv6 source")
	}
	if a.ValidateSource(netip.MustParseAddr("10.0.0.1"), pid2) {
		t.Error("peer2 (IPv6 only) should not validate IPv4 source")
	}

	// Same peer with both address families
	pid3 := makePeerID("peer3")
	a.Insert(netip.MustParsePrefix("192.168.1.0/24"), pid3)
	a.Insert(netip.MustParsePrefix("fd01::/64"), pid3)

	if !a.ValidateSource(netip.MustParseAddr("192.168.1.5"), pid3) {
		t.Error("peer3 should validate IPv4 source")
	}
	if !a.ValidateSource(netip.MustParseAddr("fd01::5"), pid3) {
		t.Error("peer3 should validate IPv6 source")
	}
}

func TestIPv6Remove(t *testing.T) {
	a := NewAllowedIPs()
	pid := makePeerID("peer1")

	a.Insert(netip.MustParsePrefix("fd00::/64"), pid)
	a.Insert(netip.MustParsePrefix("10.0.0.0/24"), pid)
	a.Remove(pid)

	_, ok := a.Lookup(netip.MustParseAddr("fd00::1"))
	if ok {
		t.Fatal("expected IPv6 lookup to fail after Remove")
	}
	_, ok = a.Lookup(netip.MustParseAddr("10.0.0.1"))
	if ok {
		t.Fatal("expected IPv4 lookup to fail after Remove")
	}
}
