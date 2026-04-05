//go:build !windows

// Package platform provides OS-specific paths for config, runtime, etc.
package platform

// ConfigDir returns the directory for MION configuration files.
func ConfigDir() string { return "/etc/mion" }

// RuntimeDir returns the directory for runtime files (UNIX sockets, PID files).
func RuntimeDir() string { return "/var/run/mion" }

// SocketPath returns the UAPI socket path for a given interface name.
func SocketPath(ifname string) string {
	return RuntimeDir() + "/" + ifname + ".sock"
}
