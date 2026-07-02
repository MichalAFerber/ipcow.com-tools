package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// isPublicIP reports whether ip is a globally-routable unicast address — rejecting loopback, private
// (RFC1918 / IPv6 ULA), link-local (incl. 169.254.169.254 cloud metadata), CGNAT, multicast and the
// unspecified address. Keeps the probes from being turned into an SSRF / internal port-scan engine
// via a user-supplied host.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false // CGNAT 100.64.0.0/10 (not covered by IsPrivate)
	}
	return true
}

// safeDialControl is a net.Dialer.Control hook. It runs after DNS resolution with the actual address
// being dialed, so it rejects any connection to a non-public IP — closing SSRF and DNS rebinding.
func safeDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil || !isPublicIP(ip) {
		return fmt.Errorf("refusing to connect to non-public address %q", address)
	}
	return nil
}

// assertHostPublic resolves host and fails if it is (or resolves to) a non-public address. For the
// exec-based probes (ping / traceroute) where a Dialer.Control hook can't intercept the connection.
func assertHostPublic(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("refusing non-public address %q", host)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("could not resolve %q", host)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("host %q did not resolve", host)
	}
	for _, a := range addrs {
		if !isPublicIP(a.IP) {
			return fmt.Errorf("refusing non-public address %s (%s)", host, a.IP)
		}
	}
	return nil
}
