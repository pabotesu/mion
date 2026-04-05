// mion-quick reads a WireGuard-style configuration file and starts/stops miond.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	ifnameOrPath := os.Args[2]

	switch subcmd {
	case "up":
		if err := cmdUp(ifnameOrPath); err != nil {
			fmt.Fprintf(os.Stderr, "mion-quick up: %v\n", err)
			os.Exit(1)
		}
	case "down":
		if err := cmdDown(ifnameOrPath); err != nil {
			fmt.Fprintf(os.Stderr, "mion-quick down: %v\n", err)
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
  mion-quick up   <interface|config-file> - start miond with config
  mion-quick down <interface>             - stop miond and tear down
`)
}

// resolveConfig resolves the interface name or config path.
// If a plain name like "mion0" is given, it looks for /etc/mion/mion0.conf.
func resolveConfig(nameOrPath string) (ifname string, configPath string) {
	if strings.Contains(nameOrPath, "/") || strings.HasSuffix(nameOrPath, ".conf") {
		// It's a path
		configPath = nameOrPath
		base := filepath.Base(configPath)
		ifname = strings.TrimSuffix(base, filepath.Ext(base))
		return
	}
	// It's an interface name
	ifname = nameOrPath
	configPath = filepath.Join("/etc/mion", ifname+".conf")
	return
}

// cmdUp starts miond with the given config.
func cmdUp(nameOrPath string) error {
	ifname, configPath := resolveConfig(nameOrPath)

	// Verify config exists
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config not found: %s", configPath)
	}

	fmt.Printf("[#] Starting miond for %s (config: %s)\n", ifname, configPath)

	// Start miond as a background process
	cmd := exec.Command("miond", "-config", configPath, "-interface", ifname)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start miond: %w", err)
	}

	fmt.Printf("[#] miond started (pid=%d)\n", cmd.Process.Pid)
	return nil
}

// cmdDown stops miond for the given interface.
func cmdDown(nameOrPath string) error {
	ifname, _ := resolveConfig(nameOrPath)

	fmt.Printf("[#] Stopping miond for %s\n", ifname)

	// Send SIGTERM to miond via pkill (simple approach)
	// In a production implementation, we'd read a PID file or use the UAPI socket.
	cmd := exec.Command("pkill", "-f", fmt.Sprintf("miond.*-interface.*%s", ifname))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop miond (is it running?): %w", err)
	}

	fmt.Printf("[#] miond stopped for %s\n", ifname)
	return nil
}
