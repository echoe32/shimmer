// Package geo resolves an IP to a country and ASN.
package geo

import (
	"context"
	"net/netip"
)

// Info is what a lookup yields.
type Info struct {
	Country string // ISO 3166-1 alpha-2
	ASN     uint
	Org     string
}

// Lookup resolves an address. The mmdb implementation is offline and fast; the
// echo implementation reports the true exit IP as seen from outside.
type Lookup interface {
	Lookup(ctx context.Context, addr netip.Addr) (*Info, error)
}
