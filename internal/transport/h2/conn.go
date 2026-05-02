// Package h2 will provide an HTTP/2 implementation of transport.TunnelConn
// using Extended CONNECT (RFC 8441) and the Capsule Protocol (RFC 9297).
//
// Unlike HTTP/3 QUIC DATAGRAMs, HTTP/2 runs over TCP (a byte stream).
// Each IP packet must be framed as a Capsule before transmission:
//
//	Capsule Type (varint=0x00) | Length (varint) | IP packet bytes
//
// The receiver reads Length first, then reads exactly that many bytes
// to reconstruct one IP packet, preserving packet boundaries.
//
// Status: stub - all methods return ErrNotImplemented.
// Full implementation is planned for the MALON Transport Manager.
package h2

import "errors"

// ErrNotImplemented is returned by all Conn methods until the HTTP/2
// Capsule Protocol framing implementation is complete.
var ErrNotImplemented = errors.New("h2: transport not yet implemented")

// Conn is the future HTTP/2 TunnelConn implementation.
type Conn struct{}

// ReadPacket is not yet implemented.
func (c *Conn) ReadPacket(buf []byte) (int, error) { return 0, ErrNotImplemented }

// WritePacket is not yet implemented.
func (c *Conn) WritePacket(pkt []byte) error { return ErrNotImplemented }

// Close is a no-op on the stub.
func (c *Conn) Close() error { return nil }
