// Package ipc provides the UAPI (Userspace API) listener
// between miond and the mion CLI tool, inspired by wireguard-go's UAPI.
// Communication happens over UNIX domain sockets using a text-based key=value protocol.
package ipc

import (
	"fmt"
	"net"
	"os"

	"github.com/pabotesu/mion/internal/platform"
)

// UAPIListener listens for UAPI connections on a UNIX domain socket.
type UAPIListener struct {
	listener net.Listener
	sockPath string
}

// NewUAPIListener creates a UNIX domain socket listener at the standard path.
func NewUAPIListener(ifname string) (*UAPIListener, error) {
	sockPath := platform.SocketPath(ifname)

	// Ensure runtime directory exists
	if err := os.MkdirAll(platform.RuntimeDir(), 0o750); err != nil {
		return nil, fmt.Errorf("ipc: failed to create runtime dir: %w", err)
	}

	// Remove stale socket if it exists
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("ipc: failed to listen on %s: %w", sockPath, err)
	}

	// Set socket permissions: owner + group can connect
	if err := os.Chmod(sockPath, 0o660); err != nil {
		listener.Close()
		return nil, fmt.Errorf("ipc: failed to chmod socket: %w", err)
	}

	return &UAPIListener{
		listener: listener,
		sockPath: sockPath,
	}, nil
}

// Accept waits for and returns the next UAPI connection.
func (u *UAPIListener) Accept() (net.Conn, error) {
	return u.listener.Accept()
}

// Close closes the listener and removes the socket file.
func (u *UAPIListener) Close() error {
	err := u.listener.Close()
	os.Remove(u.sockPath)
	return err
}

// Addr returns the socket path.
func (u *UAPIListener) Addr() string {
	return u.sockPath
}
