// Package version provides the mion version string.
// It can be overridden at build time with:
//
//	go build -ldflags "-X github.com/pabotesu/mion/internal/version.Version=v0.1.0"
package version

// Version is the current mion version.
// Overridden by -ldflags at build time.
var Version = "dev"
