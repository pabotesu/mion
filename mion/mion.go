// Package mion re-exports the core Mion type and related types for use by
// external modules (e.g. MALON) that need to drive the MION instance directly.
//
// internal/mion contains the full implementation. This package provides a
// thin public surface via type aliases so that external callers can call all
// methods (including StartForwardConnToTUN) without duplication.
package mion

import (
	internalmion "github.com/pabotesu/mion/internal/mion"
)

// Mion is the core MION instance. See internal/mion for full documentation.
type Mion = internalmion.Mion

// Config holds the runtime configuration for a Mion instance.
type Config = internalmion.Config

// Role determines whether a Mion instance acts as Client or Proxy.
type Role = internalmion.Role

const (
	RoleClient Role = internalmion.RoleClient
	RoleProxy  Role = internalmion.RoleProxy
)

// New creates and initializes a Mion instance.
func New(cfg Config) (*Mion, error) {
	return internalmion.New(cfg)
}
