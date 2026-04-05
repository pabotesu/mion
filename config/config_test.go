package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	input := `
[Interface]
PrivateKey = dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2
Address = 10.0.0.1/24
ListenPort = 51820
Role = proxy

[Peer]
PublicKey = dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3
AllowedIPs = 10.0.0.2/32, 192.168.1.0/24
Endpoint = 203.0.113.1:51820
PersistentKeepalive = 25
`

	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if cfg.Interface.PrivateKey != "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2" {
		t.Errorf("PrivateKey = %q", cfg.Interface.PrivateKey)
	}
	if cfg.Interface.Address != netip.MustParsePrefix("10.0.0.1/24") {
		t.Errorf("Address = %v", cfg.Interface.Address)
	}
	if cfg.Interface.ListenPort != 51820 {
		t.Errorf("ListenPort = %d", cfg.Interface.ListenPort)
	}
	if cfg.Interface.Role != "proxy" {
		t.Errorf("Role = %q", cfg.Interface.Role)
	}

	if len(cfg.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.PublicKey != "dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3" {
		t.Errorf("PublicKey = %q", p.PublicKey)
	}
	if len(p.AllowedIPs) != 2 {
		t.Fatalf("expected 2 AllowedIPs, got %d", len(p.AllowedIPs))
	}
	if p.Endpoint != "203.0.113.1:51820" {
		t.Errorf("Endpoint = %q", p.Endpoint)
	}
	if p.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %d", p.PersistentKeepalive)
	}
}

func TestParseMultiplePeers(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5

[Peer]
PublicKey = cGVlcjE=
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = cGVlcjI=
AllowedIPs = 10.0.0.3/32
`
	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(cfg.Peers))
	}
}

func TestParseComments(t *testing.T) {
	input := `
# This is a comment
[Interface]
# Another comment
PrivateKey = a2V5
`
	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Interface.PrivateKey != "a2V5" {
		t.Errorf("PrivateKey = %q", cfg.Interface.PrivateKey)
	}
}

func TestParseInvalidRole(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5
Role = invalid
`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for invalid Role")
	}
}

func TestParseInvalidLine(t *testing.T) {
	input := `
[Interface]
this is not valid
`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for invalid line")
	}
}
