// miond is the MION daemon process.
// It establishes and maintains L3 overlay connections via MASQUE CONNECT-IP
// sessions, and forwards L3 packets between TUN and peers.
// Requires elevated privileges (sudo / CAP_NET_ADMIN) for TUN device creation.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/pabotesu/mion/config"
	"github.com/pabotesu/mion/internal/daemon"
	"github.com/pabotesu/mion/internal/identity"
	"github.com/pabotesu/mion/internal/ipc"
	"github.com/pabotesu/mion/internal/mion"
	"github.com/pabotesu/mion/internal/platform"
	"github.com/pabotesu/mion/peer"
	"github.com/pabotesu/mion/internal/version"
)

func main() {
	configPath := flag.String("config", "/etc/mion/mion0.conf", "path to config file")
	ifaceName := flag.String("interface", "mion0", "TUN interface name")
	flag.Parse()

	log.Printf("[miond] mion %s starting", version.Version)
	if err := run(*configPath, *ifaceName); err != nil {
		log.Fatalf("[miond] fatal: %v", err)
	}
}

func run(configPath, ifaceName string) error {
	// 1. Load config file
	f, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config %s: %w", configPath, err)
	}
	defer f.Close()

	cfg, err := config.Parse(f)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// 2. Decode private key
	privKeyBytes, err := base64.StdEncoding.DecodeString(cfg.Interface.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid PrivateKey: %w", err)
	}
	if len(privKeyBytes) != ed25519.SeedSize && len(privKeyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid PrivateKey length: %d", len(privKeyBytes))
	}
	var privKey ed25519.PrivateKey
	if len(privKeyBytes) == ed25519.SeedSize {
		privKey = ed25519.NewKeyFromSeed(privKeyBytes)
	} else {
		privKey = privKeyBytes
	}

	// 3. Determine role
	role := mion.RoleClient
	if strings.ToLower(cfg.Interface.Role) == "proxy" {
		role = mion.RoleProxy
	}

	// 4. Create Mion instance
	m, err := mion.New(mion.Config{
		InterfaceName:   ifaceName,
		ListenPort:      cfg.Interface.ListenPort,
		ListenEndpoints: cfg.Interface.ListenEndpoints,
		PrivateKey:      privKey,
		Address:         cfg.Interface.Address,
		Role:            role,
	})
	if err != nil {
		return fmt.Errorf("failed to create mion instance: %w", err)
	}

	// 5. Register peers
	for _, pc := range cfg.Peers {
		p, err := peerFromConfig(pc)
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}
		if err := m.AddPeer(p); err != nil {
			return fmt.Errorf("failed to add peer: %w", err)
		}
	}

	log.Printf("[miond] role=%s peers=%d listenPort=%d",
		cfg.Interface.Role, m.Peers().Len(), cfg.Interface.ListenPort)

	// 6. Write PID file
	pidPath := platform.PIDPath(ifaceName)
	if err := os.MkdirAll(platform.RuntimeDir(), 0o750); err != nil {
		log.Printf("[miond] warning: cannot create runtime dir: %v", err)
	} else if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o640); err != nil {
		log.Printf("[miond] warning: cannot write PID file %s: %v", pidPath, err)
	} else {
		defer os.Remove(pidPath)
		log.Printf("[miond] PID %d written to %s", os.Getpid(), pidPath)
	}

	// 7. Start UAPI listener
	uapiLn, err := ipc.NewUAPIListener(ifaceName)
	if err != nil {
		log.Printf("[miond] UAPI warning: %v (CLI control disabled)", err)
	} else {
		handler := ipc.NewHandler(m, m)
		go handler.Serve(uapiLn)
		log.Printf("[miond] UAPI listening on %s", uapiLn.Addr())
	}

	// 8. Run under daemon lifecycle (blocks until signal)
	return daemon.Run(func(ctx context.Context) error {
		defer func() {
			if uapiLn != nil {
				uapiLn.Close()
			}
		}()
		return m.Run(ctx)
	})
}

// peerFromConfig constructs a peer.Peer from a config.PeerConfig.
func peerFromConfig(pc config.PeerConfig) (*peer.Peer, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(pc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer PublicKey: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid peer PublicKey length: %d", len(pubBytes))
	}
	pubKey := ed25519.PublicKey(pubBytes)
	peerID := identity.PeerIDFromPublicKey(pubKey)

	p := &peer.Peer{
		PublicKey:  pubKey,
		PeerID:     peerID,
		AllowedIPs: pc.AllowedIPs,
	}

	if pc.Endpoint != "" {
		u, err := url.Parse(pc.Endpoint)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid peer Endpoint %q: %w", pc.Endpoint, err)
		}
		// net.SplitHostPort handles both "host:port" and "[::1]:port"
		host, portStr, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("invalid peer Endpoint address %q: %w", u.Host, err)
		}
		ep, err := netip.ParseAddrPort(net.JoinHostPort(host, portStr))
		if err != nil {
			return nil, fmt.Errorf("invalid peer Endpoint address %q: %w", u.Host, err)
		}
		p.Endpoint = ep
		p.EndpointScheme = strings.ToLower(u.Scheme) // "http3" or "http2"
		p.ConfiguredEndpoint = true
	}

	return p, nil
}
