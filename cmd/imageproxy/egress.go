// Copyright 2026 The imageproxy authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// blockedPrefixes are private, loopback, link-local (including cloud metadata
// at 169.254.169.254) and otherwise non-public ranges remote images must not
// be fetched from.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// nat64Prefix embeds an IPv4 address in its last 4 bytes, which reaches that
// IPv4 host on networks with a NAT64 gateway.
var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// denyPrivateAddress is a net.Dialer Control function that refuses to connect
// to blocked addresses. It runs after DNS resolution on the address actually
// dialed, so hostnames resolving to private IPs, DNS rebinding and redirects
// are all covered.
func denyPrivateAddress(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	ip := ap.Addr().Unmap()
	if nat64Prefix.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte(b[12:]))
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return fmt.Errorf("remote address %s is not allowed", ip)
		}
	}
	return nil
}

// privateNetworkDenyingTransport returns a transport that never connects to
// blocked addresses. It replaces the default AIA transport, whose TLS dialer
// and issuer certificate fetches would bypass the check, so origins serving
// an incomplete certificate chain will fail.
func privateNetworkDenyingTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   denyPrivateAddress,
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil // a proxy would be the address checked, not the origin
	t.DialContext = dialer.DialContext
	return t
}
