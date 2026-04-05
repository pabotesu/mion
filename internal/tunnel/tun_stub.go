//go:build !linux

package tunnel

import (
	"fmt"
	"log"
	"sync"
)

// StubDevice is a fake TUN device for development on non-Linux platforms.
// It logs packets instead of actually sending/receiving them.
type StubDevice struct {
	name string
	mtu  int
	ch   chan []byte
	once sync.Once
}

// NewStubDevice creates a new StubDevice.
func NewStubDevice(name string, mtu int) *StubDevice {
	return &StubDevice{
		name: name,
		mtu:  mtu,
		ch:   make(chan []byte, 64),
	}
}

// Read blocks until a packet is injected via InjectPacket (for testing).
func (s *StubDevice) Read(b []byte) (int, error) {
	pkt, ok := <-s.ch
	if !ok {
		return 0, fmt.Errorf("stub: device closed")
	}
	n := copy(b, pkt)
	return n, nil
}

// Write logs the packet.
func (s *StubDevice) Write(b []byte) (int, error) {
	log.Printf("[stub-tun] write %d bytes to %s", len(b), s.name)
	return len(b), nil
}

// Name returns the device name.
func (s *StubDevice) Name() string { return s.name }

// MTU returns the configured MTU.
func (s *StubDevice) MTU() int { return s.mtu }

// Close closes the device.
func (s *StubDevice) Close() error {
	s.once.Do(func() { close(s.ch) })
	return nil
}

// InjectPacket sends a packet into the Read channel (for testing).
func (s *StubDevice) InjectPacket(pkt []byte) {
	s.ch <- pkt
}

// NewDevice creates a stub device on non-Linux platforms.
// On Linux, this function is replaced by the real TUN implementation.
func NewDevice(name string, mtu int) (Device, error) {
	return NewStubDevice(name, mtu), fmt.Errorf("tunnel: real TUN not available on this platform (using stub)")
}
