// Package config parses WireGuard-style configuration files for MION.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Config represents a parsed MION configuration file.
type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

// InterfaceConfig represents the [Interface] section.
type InterfaceConfig struct {
	PrivateKey string       // base64-encoded Ed25519 private key
	Address    netip.Prefix // IP address for the TUN device
	ListenPort int          // UDP listen port (0 = OS-assigned)
	Role       string       // "client" or "proxy" (default: "client")
}

// PeerConfig represents a [Peer] section.
type PeerConfig struct {
	PublicKey           string         // base64-encoded Ed25519 public key
	AllowedIPs          []netip.Prefix // prefixes this peer is responsible for
	Endpoint            string         // host:port (empty = dynamic, roaming allowed)
	PersistentKeepalive int            // seconds (0 = disabled)
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
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("config: invalid ListenPort %q: %w", value, err)
		}
		iface.ListenPort = port
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
