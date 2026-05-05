// Package transport defines the TunnelConn interface shared across all
// transport implementations (HTTP/3 QUIC DATAGRAM, HTTP/2 Capsule, etc.).
//
// TunnelConn is the single abstraction boundary between the IP forwarding
// layer and the underlying transport.
package transport

// TunnelConn represents one established IP tunnel session.
//
// HTTP/3 (QUIC DATAGRAM):
//
//	Each ReadPacket/WritePacket call maps 1:1 to a QUIC DATAGRAM frame.
//	Packet boundaries are preserved by the QUIC transport layer.
//
// HTTP/2 (Capsule Protocol over TCP):
//
//	TCP is a byte stream. Implementations must frame each IP packet via
//	the Capsule Protocol (RFC 9297):
//	  Capsule Type (varint=0) | Length (varint) | IP packet bytes
//	ReadPacket must consume exactly one Capsule before returning.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type TunnelConn interface {
	// ReadPacket reads one complete IP packet into buf.
	// A non-nil error means the session is broken and should not be reused.
	ReadPacket(buf []byte) (int, error)

	// WritePacket sends one complete IP packet.
	// On stream-based transports (HTTP/2), a non-nil error means the session
	// is broken and the caller should trigger reconnection.
	WritePacket(pkt []byte) error

	// Close terminates the tunnel session and releases resources.
	Close() error
}
