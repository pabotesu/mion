//go:build linux

package tunnel

import (
	"fmt"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// linuxDevice wraps a real Linux TUN device.
type linuxDevice struct {
	iface *water.Interface
	name  string
	mtu   int
}

// NewDevice creates a real TUN device on Linux.
// Requires CAP_NET_ADMIN or root privileges.
func NewDevice(name string, mtu int) (Device, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = name

	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("tunnel: failed to create TUN device %q: %w", name, err)
	}

	// Set the interface up and configure MTU via netlink
	link, err := netlink.LinkByName(iface.Name())
	if err != nil {
		iface.Close()
		return nil, fmt.Errorf("tunnel: failed to find link %q: %w", iface.Name(), err)
	}

	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		iface.Close()
		return nil, fmt.Errorf("tunnel: failed to set MTU on %q: %w", iface.Name(), err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		iface.Close()
		return nil, fmt.Errorf("tunnel: failed to bring up %q: %w", iface.Name(), err)
	}

	return &linuxDevice{
		iface: iface,
		name:  iface.Name(),
		mtu:   mtu,
	}, nil
}

// ConfigureAddress adds an IP address/prefix to the TUN device.
// This is called separately after NewDevice so the caller can control timing.
func ConfigureAddress(devName string, addr net.IPNet) error {
	link, err := netlink.LinkByName(devName)
	if err != nil {
		return fmt.Errorf("tunnel: link %q not found: %w", devName, err)
	}
	nlAddr := &netlink.Addr{IPNet: &addr}
	if err := netlink.AddrAdd(link, nlAddr); err != nil {
		return fmt.Errorf("tunnel: failed to add address to %q: %w", devName, err)
	}
	return nil
}

func (d *linuxDevice) Read(b []byte) (int, error) {
	return d.iface.Read(b)
}

func (d *linuxDevice) Write(b []byte) (int, error) {
	return d.iface.Write(b)
}

func (d *linuxDevice) Name() string { return d.name }

func (d *linuxDevice) MTU() int { return d.mtu }

func (d *linuxDevice) Close() error {
	return d.iface.Close()
}
