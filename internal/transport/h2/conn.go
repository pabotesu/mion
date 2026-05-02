// Package h2 provides an HTTP/2 implementation of transport.TunnelConn.
//
// Unlike HTTP/3 QUIC DATAGRAMs, HTTP/2 runs over TCP (a byte stream).
// Each IP packet is framed using a minimal capsule format compatible with
// the Capsule Protocol (RFC 9297):
//
//	Capsule Type  (QUIC varint, value = 0 for IP_PACKET)
//	Capsule Length (QUIC varint, byte count of payload)
//	Payload        (raw IP packet bytes)
//
// The QUIC variable-length integer encoding (RFC 9000 §16) is used for both
// the type and length fields. The most-significant 2 bits of the first byte
// encode the total field width (1, 2, 4, or 8 bytes), and the remaining bits
// carry the value in big-endian order.
//
// Both client and server sides use the same Conn type. The caller supplies
// separate reader and writer streams (e.g. request-body pipe + response-body
// io.ReadCloser for the client, r.Body + http.ResponseWriter for the server).
package h2

import (
	"bufio"
	"fmt"
	"io"
	"sync"
)

// capsuleTypeIPPacket is the capsule type used for raw IP packet payloads.
// Value 0 maps to the DATAGRAM capsule type used by the Cloudflare/usque style
// HTTP/2 CONNECT-IP implementation.
const capsuleTypeIPPacket uint64 = 0

// Conn implements transport.TunnelConn over an HTTP/2 byte stream using
// capsule framing. It is safe for concurrent use by multiple goroutines.
type Conn struct {
	rd      *bufio.Reader        // source of inbound capsules
	wr      io.Writer            // sink for outbound capsules
	flusher interface{ Flush() } // http.Flusher; nil on the client side
	closer  func() error         // closes both rd source and wr sink
	wrMu    sync.Mutex
}

// NewClientConn creates a Conn for the client side of an HTTP/2 tunnel.
//
//   - pw is the io.PipeWriter used as the HTTP/2 POST request body
//     (data flows client → server).
//   - body is the HTTP/2 response body (data flows server → client).
func NewClientConn(pw *io.PipeWriter, body io.ReadCloser) *Conn {
	return &Conn{
		rd: bufio.NewReaderSize(body, 65536),
		wr: pw,
		closer: func() error {
			_ = pw.Close()
			return body.Close()
		},
	}
}

// NewServerConn creates a Conn for the server side of an HTTP/2 tunnel.
//
//   - body is the HTTP/2 request body (data flows client → server).
//   - w is the http.ResponseWriter (data flows server → client).
//   - f is the http.Flusher for w; each WritePacket call flushes immediately.
func NewServerConn(body io.ReadCloser, w io.Writer, f interface{ Flush() }) *Conn {
	return &Conn{
		rd:      bufio.NewReaderSize(body, 65536),
		wr:      w,
		flusher: f,
		closer:  body.Close,
	}
}

// ReadPacket reads one complete IP packet from the capsule stream.
// Unknown capsule types are silently discarded.
// A non-nil error means the stream is broken and the Conn should be closed.
func (c *Conn) ReadPacket(buf []byte) (int, error) {
	for {
		ct, err := readVarint(c.rd)
		if err != nil {
			return 0, fmt.Errorf("h2: capsule type: %w", err)
		}
		payloadLen, err := readVarint(c.rd)
		if err != nil {
			return 0, fmt.Errorf("h2: capsule length: %w", err)
		}
		if ct != capsuleTypeIPPacket {
			// Discard unknown capsule types (forward-compatibility).
			if _, err := io.CopyN(io.Discard, c.rd, int64(payloadLen)); err != nil {
				return 0, fmt.Errorf("h2: discard capsule type %d: %w", ct, err)
			}
			continue
		}
		if int(payloadLen) > len(buf) {
			return 0, fmt.Errorf("h2: packet (%d B) exceeds buffer (%d B)", payloadLen, len(buf))
		}
		if _, err := io.ReadFull(c.rd, buf[:payloadLen]); err != nil {
			return 0, fmt.Errorf("h2: read payload: %w", err)
		}
		return int(payloadLen), nil
	}
}

// WritePacket frames pkt as an IP_PACKET capsule and writes it to the stream.
// On the server side, the underlying writer is flushed after each call.
func (c *Conn) WritePacket(pkt []byte) error {
	hdr := appendVarint(nil, capsuleTypeIPPacket)
	hdr = appendVarint(hdr, uint64(len(pkt)))
	c.wrMu.Lock()
	defer c.wrMu.Unlock()
	if _, err := c.wr.Write(hdr); err != nil {
		return fmt.Errorf("h2: write capsule header: %w", err)
	}
	if _, err := c.wr.Write(pkt); err != nil {
		return fmt.Errorf("h2: write capsule payload: %w", err)
	}
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return nil
}

// Close closes the underlying streams.
func (c *Conn) Close() error {
	return c.closer()
}

// readVarint reads one QUIC variable-length integer (RFC 9000 §16) from r.
func readVarint(r io.ByteReader) (uint64, error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	length := 1 << (b0 >> 6)
	val := uint64(b0 & 0x3f)
	for i := 1; i < length; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		val = (val << 8) | uint64(b)
	}
	return val, nil
}

// appendVarint appends a QUIC variable-length integer (RFC 9000 §16) to b.
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(b, byte(v))
	case v < 16384:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1073741824:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
