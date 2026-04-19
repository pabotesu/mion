//go:build darwin

package tunnel

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

// darwinDevice wraps a macOS utun TUN device.
type darwinDevice struct {
	iface *water.Interface
	name  string
	mtu   int
}

// NewDevice creates a real TUN device on macOS using utun.
// Requires root privileges or appropriate entitlements.
func NewDevice(name string, mtu int) (Device, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
	}
	// water on macOS ignores the Name field and assigns utunN automatically.
	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("tunnel: failed to create utun device: %w", err)
	}

	// Set MTU via ifconfig
	if err := exec.Command("ifconfig", iface.Name(), "mtu", fmt.Sprintf("%d", mtu), "up").Run(); err != nil {
		iface.Close()
		return nil, fmt.Errorf("tunnel: failed to set MTU on %q: %w", iface.Name(), err)
	}

	return &darwinDevice{
		iface: iface,
		name:  iface.Name(),
		mtu:   mtu,
	}, nil
}

// ConfigureAddress adds an IPv4 address to the utun device using ifconfig.
// macOS utun requires point-to-point style: ifconfig <dev> inet <addr> <addr>
func ConfigureAddress(devName string, addr net.IPNet) error {
	ip := addr.IP.String()
	if err := exec.Command("ifconfig", devName, "inet", ip, ip).Run(); err != nil {
		return fmt.Errorf("tunnel: failed to add address to %q: %w", devName, err)
	}
	// Add a route for the overlay subnet so the kernel can forward packets.
	bits, _ := addr.Mask.Size()
	prefix := fmt.Sprintf("%s/%d", addr.IP.Mask(addr.Mask).String(), bits)
	if err := exec.Command("route", "-q", "-n", "add", "-inet", prefix, "-interface", devName).Run(); err != nil {
		return fmt.Errorf("tunnel: failed to add route %s on %q: %w", prefix, devName, err)
	}
	return nil
}

func (d *darwinDevice) Read(b []byte) (int, error) {
	return d.iface.Read(b)
}

func (d *darwinDevice) Write(b []byte) (int, error) {
	return d.iface.Write(b)
}

func (d *darwinDevice) Name() string { return d.name }

func (d *darwinDevice) MTU() int { return d.mtu }

func (d *darwinDevice) Close() error {
	return d.iface.Close()
}
