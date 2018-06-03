package diag

import "net"

var (
	global = mustParseCIDR("2000::/3") // RFC 4291
)

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, _ := net.ParseCIDR(s)
	return ipnet
}
