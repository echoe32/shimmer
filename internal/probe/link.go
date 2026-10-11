package probe

import (
	"context"
	"net"
	"strconv"
	"time"

	"shimmer/internal/dial"
)

// ProbeLink proves that a share link forwards traffic: it asks the check
// endpoint for its answer through t, a dialer that already carries
// connections through the link. Completing the link's handshake is not
// enough, for the same reasons as with a SOCKS proxy.
//
// It reports how long the request took, from the dial to the answer, the
// handshake with the link's server included.
func ProbeLink(ctx context.Context, t dial.Dialer, c Check) (time.Duration, error) {
	start := time.Now()
	conn, err := t.DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	defer guard(ctx, conn)()

	if err := verifyOrigin(conn, c); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
