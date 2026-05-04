// mion-quick reads a WireGuard-style configuration file and starts/stops miond.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/pabotesu/mion/internal/platform"
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

// cmdDown stops miond for the given interface using the PID file.
func cmdDown(nameOrPath string) error {
	ifname, _ := resolveConfig(nameOrPath)

	pidPath := platform.PIDPath(ifname)
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Errorf("cannot read PID file %s (is miond running?): %w", pidPath, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid PID file %s: %w", pidPath, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("cannot find process %d: %w", pid, err)
	}

	fmt.Printf("[#] Stopping miond (pid=%d) for %s\n", pid, ifname)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to signal miond (pid=%d): %w", pid, err)
	}

	fmt.Printf("[#] miond stopped for %s\n", ifname)
	return nil
}
