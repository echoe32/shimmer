package probe

import (
	"context"
	"time"

	"shimmer/internal/dial"
)

// ConnectRTT measures the TCP handshake to the proxy. This
// is the closest honest analogue to a ping: ICMP cannot traverse a proxy.
func ConnectRTT(ctx context.Context, d dial.Dialer, p Proxy) (time.Duration, error) {
	conn, rtt, err := dialProxy(ctx, d, p)
	if err != nil {
		return rtt, err
	}
	conn.Close()
	return rtt, nil
}
