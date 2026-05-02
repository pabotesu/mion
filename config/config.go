// Package config parses WireGuard-style configuration files for MION.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Config represents a parsed MION configuration file.
type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

// ListenEndpoint represents a single listen address used by the proxy.
//
// Format: scheme://[host]:port
//
// Examples:
//
//	ListenPort = http3://:443                    → [{"http3", "", 443}]
//	ListenPort = http2://:4443, http3://:443     → [{"http2", "", 4443}, {"http3", "", 443}]
//	ListenPort = http3://192.168.1.1:8443        → [{"http3", "192.168.1.1", 8443}]
type ListenEndpoint struct {
	Protocol string // "http2" or "http3"
	Host     string // bind address; empty string means all interfaces
	Port     int
}

// InterfaceConfig represents the [Interface] section.
type InterfaceConfig struct {
	PrivateKey      string           // base64-encoded Ed25519 private key
	Address         netip.Prefix     // IP address for the TUN device
	ListenEndpoints []ListenEndpoint // parsed from ListenPort field
	ListenPort      int              // first http3 port for backward compat (0 = none)
	Role            string           // "client" or "proxy" (default: "client")
}

// PeerConfig represents a [Peer] section.
type PeerConfig struct {
	PublicKey  string         // base64-encoded Ed25519 public key
	AllowedIPs []netip.Prefix // prefixes this peer is responsible for
	// Endpoint is the proxy address for this peer.
	// Must include a scheme:
	//   "http3://host:port"  — HTTP/3 (QUIC) transport
	//   "http2://host:port"  — HTTP/2 (TLS/TCP) transport
	Endpoint            string
	PersistentKeepalive int // seconds (0 = disabled)
}

// Parse reads a WireGuard-style config from r.
func Parse(r io.Reader) (*Config, error) {
	cfg := &Config{}
	scanner := bufio.NewScanner(r)
	var section string
	var currentPeer *PeerConfig

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section headers
		if line == "[Interface]" {
			section = "interface"
			continue
		}
		if line == "[Peer]" {
			section = "peer"
			cfg.Peers = append(cfg.Peers, PeerConfig{})
			currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			continue
		}

		// Key = Value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("config: invalid line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			if err := parseInterfaceField(&cfg.Interface, key, value); err != nil {
				return nil, err
			}
		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("config: key %s outside [Peer] section", key)
			}
			if err := parsePeerField(currentPeer, key, value); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("config: key %s outside any section", key)
		}
	}

	return cfg, scanner.Err()
}

func parseInterfaceField(iface *InterfaceConfig, key, value string) error {
	switch key {
	case "PrivateKey":
		iface.PrivateKey = value
	case "Address":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("config: invalid Address %q: %w", value, err)
		}
		iface.Address = prefix
	case "ListenPort":
		ends, err := parseListenEndpoints(value)
		if err != nil {
			return fmt.Errorf("config: invalid ListenPort %q: %w", value, err)
		}
		iface.ListenEndpoints = ends
		// Populate legacy ListenPort with the first http3 port for backward compat.
		for _, e := range ends {
			if e.Protocol == "http3" {
				iface.ListenPort = e.Port
				break
			}
		}
	case "Role":
		switch strings.ToLower(value) {
		case "client", "proxy":
			iface.Role = strings.ToLower(value)
		default:
			return fmt.Errorf("config: invalid Role %q (must be 'client' or 'proxy')", value)
		}
	default:
		return fmt.Errorf("config: unknown Interface key %q", key)
	}
	return nil
}

func parsePeerField(peer *PeerConfig, key, value string) error {
	switch key {
	case "PublicKey":
		peer.PublicKey = value
	case "AllowedIPs":
		for _, s := range strings.Split(value, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return fmt.Errorf("config: invalid AllowedIPs %q: %w", s, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, prefix)
		}
	case "Endpoint":
		if err := validateEndpoint(value); err != nil {
			return fmt.Errorf("config: invalid Endpoint %q: %w", value, err)
		}
		peer.Endpoint = value
	case "PersistentKeepalive":
		secs, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("config: invalid PersistentKeepalive %q: %w", value, err)
		}
		peer.PersistentKeepalive = secs
	default:
		return fmt.Errorf("config: unknown Peer key %q", key)
	}
	return nil
}

// parseListenEndpoints parses the ListenPort field value into ListenEndpoints.
//
// Required format: scheme://[host]:port
//
//	"http3://:443"                → [{"http3", "", 443}]
//	"http2://:4443, http3://:443" → [{"http2", "", 4443}, {"http3", "", 443}]
//	"http3://192.168.1.1:8443"    → [{"http3", "192.168.1.1", 8443}]
func parseListenEndpoints(value string) ([]ListenEndpoint, error) {
	var ends []ListenEndpoint
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, err := url.Parse(part)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid ListenPort entry %q: use http3://:port or http2://:port", part)
		}
		proto := strings.ToLower(u.Scheme)
		if proto != "http2" && proto != "http3" {
			return nil, fmt.Errorf("unknown protocol %q in %q (use http2:// or http3://)", proto, part)
		}
		host, portStr, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("invalid address in %q: %w", part, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port in %q", part)
		}
		ends = append(ends, ListenEndpoint{Protocol: proto, Host: host, Port: port})
	}
	if len(ends) == 0 {
		return nil, fmt.Errorf("no valid endpoints found")
	}
	return ends, nil
}

// validateEndpoint checks that the Endpoint value uses a supported scheme.
//
// Accepted formats:
//
//	"http3://host:port"   — explicit HTTP/3
//	"http2://host:port"   — explicit HTTP/2
func validateEndpoint(value string) error {
	if strings.HasPrefix(value, "http3://") || strings.HasPrefix(value, "http2://") {
		return nil
	}
	return fmt.Errorf("Endpoint %q must specify a scheme: use http3:// or http2://", value)
}
