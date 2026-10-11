// Package dial holds the outbound seam every probe connection goes through.
package dial

import (
	"context"
	"net"
)

// Dialer is the seam every outbound connection goes through. A plain
// net.Dialer satisfies it; tests substitute their own.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Tunnel is a Dialer that holds a route open, such as a share link's
// outbound, until it is closed.
type Tunnel interface {
	Dialer
	Close() error
}
