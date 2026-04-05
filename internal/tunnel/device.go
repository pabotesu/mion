// Package tunnel provides the TUN device abstraction.
// Implementations are provided per-platform via build tags.
package tunnel

// Device is the interface for reading/writing L3 packets from/to a TUN device.
// Implementations:
//   - tun_linux.go: real TUN device via water + netlink
//   - tun_stub.go:  stub for development on non-Linux (logs packets)
type Device interface {
	// Read reads a single IP packet from the TUN device into b.
	// Returns the number of bytes read.
	Read(b []byte) (int, error)

	// Write writes a single IP packet to the TUN device.
	Write(b []byte) (int, error)

	// Name returns the OS interface name (e.g., "mion0", "utun3").
	Name() string

	// MTU returns the MTU of the device.
	MTU() int

	// Close tears down the TUN device.
	Close() error
}
