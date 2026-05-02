// Package h3 provides an HTTP/3 implementation of transport.TunnelConn
// by wrapping *connectip.Conn from the connect-ip-go library.
//
// Packet framing: QUIC DATAGRAM frames guarantee one-packet-per-frame
// semantics, so ReadPacket and WritePacket never straddle frame boundaries.
package h3

import connectip "github.com/quic-go/connect-ip-go"

// Conn adapts *connectip.Conn to the transport.TunnelConn interface.
// It is safe for concurrent use by multiple goroutines.
type Conn struct {
	inner *connectip.Conn
}

// New wraps c as a transport.TunnelConn.
// The caller must not use c directly after passing it to New.
func New(c *connectip.Conn) *Conn {
	return &Conn{inner: c}
}

// ReadPacket reads one IP packet from the underlying QUIC DATAGRAM stream.
func (c *Conn) ReadPacket(buf []byte) (int, error) {
	return c.inner.ReadPacket(buf)
}

// WritePacket sends one IP packet as a single QUIC DATAGRAM frame.
func (c *Conn) WritePacket(pkt []byte) error {
	_, err := c.inner.WritePacket(pkt)
	return err
}

// Close closes the CONNECT-IP session.
func (c *Conn) Close() error {
	return c.inner.Close()
}
