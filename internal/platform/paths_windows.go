//go:build windows

// Package platform provides OS-specific paths for config, runtime, etc.
package platform

// ConfigDir returns the directory for MION configuration files.
func ConfigDir() string { return `C:\ProgramData\mion` }

// RuntimeDir returns the directory for runtime files (named pipes, PID files).
func RuntimeDir() string { return `\\.\pipe\mion` }

// SocketPath returns the UAPI named pipe path for a given interface name.
func SocketPath(ifname string) string {
	return `\\.\pipe\mion\` + ifname
}

// PIDPath returns the PID file path for a given interface name.
func PIDPath(ifname string) string {
	return `C:\ProgramData\mion\` + ifname + ".pid"
}
