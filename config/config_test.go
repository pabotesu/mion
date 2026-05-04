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
ListenPort = http3://:51820
Role = proxy

[Peer]
PublicKey = dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3
AllowedIPs = 10.0.0.2/32, 192.168.1.0/24
Endpoint = http3://203.0.113.1:51820
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
	// ListenPort derived from first http3 entry.
	if cfg.Interface.ListenPort != 51820 {
		t.Errorf("ListenPort = %d", cfg.Interface.ListenPort)
	}
	if len(cfg.Interface.ListenEndpoints) != 1 {
		t.Fatalf("expected 1 ListenEndpoint, got %d", len(cfg.Interface.ListenEndpoints))
	}
	if cfg.Interface.ListenEndpoints[0] != (ListenEndpoint{Protocol: "http3", Host: "", Port: 51820}) {
		t.Errorf("ListenEndpoints[0] = %+v", cfg.Interface.ListenEndpoints[0])
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
	if p.Endpoint != "http3://203.0.113.1:51820" {
		t.Errorf("Endpoint = %q", p.Endpoint)
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

func TestParseListenEndpointsScheme(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5
ListenPort = http2://:4443, http3://:443
`
	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(cfg.Interface.ListenEndpoints) != 2 {
		t.Fatalf("expected 2 ListenEndpoints, got %d", len(cfg.Interface.ListenEndpoints))
	}
	if cfg.Interface.ListenEndpoints[0] != (ListenEndpoint{Protocol: "http2", Host: "", Port: 4443}) {
		t.Errorf("[0] = %+v", cfg.Interface.ListenEndpoints[0])
	}
	if cfg.Interface.ListenEndpoints[1] != (ListenEndpoint{Protocol: "http3", Host: "", Port: 443}) {
		t.Errorf("[1] = %+v", cfg.Interface.ListenEndpoints[1])
	}
	// ListenPort derives from first http3 entry.
	if cfg.Interface.ListenPort != 443 {
		t.Errorf("ListenPort = %d, want 443", cfg.Interface.ListenPort)
	}
}

func TestParseListenEndpointsSingleScheme(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5
ListenPort = http3://:8443
`
	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(cfg.Interface.ListenEndpoints) != 1 {
		t.Fatalf("expected 1 ListenEndpoint, got %d", len(cfg.Interface.ListenEndpoints))
	}
	if cfg.Interface.ListenEndpoints[0].Protocol != "http3" || cfg.Interface.ListenEndpoints[0].Host != "" || cfg.Interface.ListenEndpoints[0].Port != 8443 {
		t.Errorf("unexpected endpoint: %+v", cfg.Interface.ListenEndpoints[0])
	}
	if cfg.Interface.ListenPort != 8443 {
		t.Errorf("ListenPort = %d, want 8443", cfg.Interface.ListenPort)
	}
}

func TestParseListenEndpointsInvalidScheme(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5
ListenPort = grpc://:4443
`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestParseEndpointSchemeHTTP3(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5

[Peer]
PublicKey = cGVlcjE=
AllowedIPs = 10.0.0.2/32
Endpoint = http3://203.0.113.1:4443
`
	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Peers[0].Endpoint != "http3://203.0.113.1:4443" {
		t.Errorf("Endpoint = %q", cfg.Peers[0].Endpoint)
	}
}

func TestParseEndpointSchemeHTTP2(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5

[Peer]
PublicKey = cGVlcjE=
AllowedIPs = 10.0.0.2/32
Endpoint = http2://203.0.113.1:4443
`
	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Peers[0].Endpoint != "http2://203.0.113.1:4443" {
		t.Errorf("Endpoint = %q", cfg.Peers[0].Endpoint)
	}
}

func TestParseEndpointUnknownScheme(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5

[Peer]
PublicKey = cGVlcjE=
AllowedIPs = 10.0.0.2/32
Endpoint = grpc://203.0.113.1:4443
`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for unknown Endpoint scheme")
	}
}

func TestParseListenEndpointPlainNumberRejected(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5
ListenPort = 51820
`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error: plain port number must use http3://:port or http2://:port")
	}
}

func TestParseListenEndpointSpecificHost(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5
ListenPort = http3://192.168.1.1:8443
`
	cfg, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	ep := cfg.Interface.ListenEndpoints[0]
	if ep.Protocol != "http3" || ep.Host != "192.168.1.1" || ep.Port != 8443 {
		t.Errorf("unexpected endpoint: %+v", ep)
	}
}

func TestParseEndpointPlainHostPortRejected(t *testing.T) {
	input := `
[Interface]
PrivateKey = a2V5

[Peer]
PublicKey = cGVlcjE=
AllowedIPs = 10.0.0.2/32
Endpoint = 203.0.113.1:51820
`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error: plain host:port should require http3:// or http2:// scheme")
	}
}
