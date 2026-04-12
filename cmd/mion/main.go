// mion is the CLI tool for interacting with a running miond instance.
// It communicates with miond via UNIX domain socket using the UAPI protocol.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/pabotesu/mion/internal/platform"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	subcmd := os.Args[1]

	// Subcommands that don't require an interface name
	switch subcmd {
	case "genkey":
		if err := cmdGenkey(); err != nil {
			fmt.Fprintf(os.Stderr, "mion genkey: %v\n", err)
			os.Exit(1)
		}
		return
	case "pubkey":
		if err := cmdPubkey(); err != nil {
			fmt.Fprintf(os.Stderr, "mion pubkey: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Subcommands that require an interface name
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}
	ifname := os.Args[2]

	switch subcmd {
	case "show":
		if err := cmdShow(ifname); err != nil {
			fmt.Fprintf(os.Stderr, "mion show: %v\n", err)
			os.Exit(1)
		}
	case "set":
		if err := cmdSet(ifname, os.Args[3:]); err != nil {
			fmt.Fprintf(os.Stderr, "mion set: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", subcmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  mion genkey                         - generate a new Ed25519 private key
  mion pubkey                         - derive public key from private key (stdin)
  mion show <interface>               - display device and peer status
  mion set  <interface> key=value ... - modify configuration at runtime

Key generation:
  mion genkey | tee privatekey | mion pubkey > publickey

Runtime set keys:
	public_key=<base64>                 - select/create peer by Ed25519 public key
	peer_id=<base64>                    - select/create peer by explicit PeerID
	endpoint=<host:port>                - set peer endpoint (triggers reconnect)
	allowed_ip=<cidr>                   - add allowed prefix to peer
	persistent_keepalive_interval=<sec> - set keepalive interval
	remove=true                         - remove selected peer

Examples:
	# Add a new peer
	mion set mion0 \
		public_key=BASE64PUBKEY \
		endpoint=203.0.113.10:4443 \
		allowed_ip=100.100.0.10/32 \
		persistent_keepalive_interval=25

	# Update existing peer endpoint (runtime reconnect)
	mion set mion0 public_key=BASE64PUBKEY endpoint=198.51.100.5:4443

	# Remove a peer
	mion set mion0 public_key=BASE64PUBKEY remove=true

	# Batch update multiple peers in one command
	mion set mion0 \
		public_key=PEER_A endpoint=203.0.113.11:4443 allowed_ip=100.100.0.11/32 \
		public_key=PEER_B endpoint=203.0.113.12:4443 allowed_ip=100.100.0.12/32
`)
}

// uapiDial connects to the miond UNIX socket for the given interface.
func uapiDial(ifname string) (net.Conn, error) {
	sockPath := platform.SocketPath(ifname)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to miond (is it running?): %w", err)
	}
	return conn, nil
}

// uapiRequest sends a UAPI request and returns the response lines.
func uapiRequest(ifname, request string) ([]string, error) {
	conn, err := uapiDial(ifname)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send the request line followed by a newline
	if _, err := fmt.Fprintf(conn, "%s\n", request); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response lines until EOF or empty line
	var lines []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	return lines, nil
}

// cmdGenkey generates a new Ed25519 private key and prints it as base64 to stdout.
func cmdGenkey() error {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	// Output the 32-byte seed (same convention as WireGuard's 32-byte private key)
	fmt.Println(base64.StdEncoding.EncodeToString(priv.Seed()))
	return nil
}

// cmdPubkey reads a base64-encoded private key from stdin and prints
// the corresponding public key to stdout.
func cmdPubkey() error {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}
	privB64 := strings.TrimSpace(string(raw))
	seed, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid key length: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

// cmdShow queries the running daemon for the current device and peer state.
func cmdShow(ifname string) error {
	lines, err := uapiRequest(ifname, "get=1")
	if err != nil {
		return err
	}

	if len(lines) == 0 {
		fmt.Printf("interface: %s (no data)\n", ifname)
		return nil
	}

	fmt.Printf("interface: %s\n", ifname)
	inPeer := false
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		switch key {
		case "private_key":
			fmt.Printf("  private key: (hidden)\n")
		case "listen_port":
			fmt.Printf("  listening port: %s\n", val)
		case "public_key":
			if inPeer {
				fmt.Println() // separator between peers
			}
			fmt.Printf("\npeer:\n")
			fmt.Printf("  public key: %s\n", val)
			inPeer = true
		case "peer_id":
			if !inPeer {
				fmt.Printf("\npeer:\n")
				inPeer = true
			}
			fmt.Printf("  peer id: %s\n", val)
		case "endpoint":
			fmt.Printf("  endpoint: %s\n", val)
		case "allowed_ip":
			fmt.Printf("  allowed ips: %s\n", val)
		case "persistent_keepalive_interval":
			fmt.Printf("  persistent keepalive: every %s seconds\n", val)
		default:
			fmt.Printf("  %s: %s\n", key, val)
		}
	}
	fmt.Println()
	return nil
}

// cmdSet sends set commands to the running daemon.
func cmdSet(ifname string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no key=value pairs specified")
	}

	// Build a UAPI set request
	req := "set=1\n" + strings.Join(args, "\n") + "\n"
	lines, err := uapiRequest(ifname, req)
	if err != nil {
		return err
	}

	status := ""
	errorText := ""
	summary := map[string]string{}

	// Check for errno=0 (success)
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		switch key {
		case "errno":
			if val != "0" {
				if errorText == "" {
					return fmt.Errorf("daemon returned error: errno=%s", val)
				}
				return fmt.Errorf("daemon returned error: %s", errorText)
			}
		case "status":
			status = val
		case "error":
			errorText = val
		case "applied_peers", "added_peers", "removed_peers", "reconnected_peers":
			summary[key] = val
		}
	}

	fmt.Printf("Configuration updated for %s", ifname)
	if status != "" {
		fmt.Printf(" (status=%s)", status)
	}
	fmt.Printf("\n")

	if len(summary) > 0 {
		fmt.Printf("  applied peers: %s\n", summary["applied_peers"])
		fmt.Printf("  added peers: %s\n", summary["added_peers"])
		fmt.Printf("  removed peers: %s\n", summary["removed_peers"])
		fmt.Printf("  reconnected peers: %s\n", summary["reconnected_peers"])
	}
	return nil
}
