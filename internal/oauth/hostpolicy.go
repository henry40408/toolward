package oauth

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// The rules below follow the metadata host policy of rmcp 3.9.0. The resource
// controls the metadata it serves, so a URL named there must not lead the
// client to an internal address.

var cloudMetadataHosts = []string{"metadata", "metadata.google.internal", "metadata.azure.internal"}

func isHTTPURL(u *url.URL) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

func portOf(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func sameOrigin(base, candidate *url.URL) bool {
	return base.Scheme == candidate.Scheme &&
		strings.EqualFold(base.Hostname(), candidate.Hostname()) &&
		portOf(base) == portOf(candidate)
}

// normalizeHost lowercases a host and drops the trailing dot of a root label.
func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimRight(host, "."))
}

func isLoopbackName(host string) bool {
	host = normalizeHost(host)
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func isLoopbackHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return isLoopbackName(host)
}

func isDisallowedHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return isDisallowedIP(ip)
	}
	host = normalizeHost(host)
	if isLoopbackName(host) {
		return true
	}
	for _, name := range cloudMetadataHosts {
		if host == name {
			return true
		}
	}
	return false
}

// isAllowedMetadataURL accepts a http(s) URL whose host is not internal. An
// internal host is accepted only when the resource itself is on loopback.
func isAllowedMetadataURL(base, candidate *url.URL) bool {
	if !isHTTPURL(candidate) {
		return false
	}
	host := candidate.Hostname()
	if !isDisallowedHost(host) {
		return true
	}
	return isLoopbackHost(base.Hostname()) && isLoopbackHost(host)
}

func isDisallowedIP(ip netip.Addr) bool {
	ip = ip.WithZone("")
	if embedded, ok := embeddedIPv4(ip); ok {
		return isDisallowedIPv4(embedded)
	}
	if ip.Is4() {
		return isDisallowedIPv4(ip)
	}
	bytes := ip.As16()
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || bytes[0]&0xfe == 0xfc ||
		(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0) ||
		(bytes[0] == 0 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b && bytes[4] == 0 && bytes[5] == 1)
}

func isDisallowedIPv4(ip netip.Addr) bool {
	octets := ip.As4()
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) ||
		octets[0] == 0 ||
		(octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127) ||
		(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
}

// embeddedIPv4 returns the IPv4 address that IPv4-mapped, IPv4-compatible,
// NAT64 (64:ff9b::/96) and 6to4 (2002::/16) addresses carry.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if ip.Is4() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	low := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	switch {
	case isZero(b[:10]) && b[10] == 0xff && b[11] == 0xff:
		return low, true
	case b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && isZero(b[4:12]):
		return low, true
	case isZero(b[:12]) && !ip.IsLoopback() && !ip.IsUnspecified():
		return low, true
	case b[0] == 0x20 && b[1] == 0x02:
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

func isZero(bytes []byte) bool {
	for _, b := range bytes {
		if b != 0 {
			return false
		}
	}
	return true
}

type addressClass int

const (
	classPublic addressClass = iota
	classLoopback
	classPrivate
	classBlocked
)

func classOf(ip netip.Addr) addressClass {
	ip = ip.WithZone("")
	if embedded, ok := embeddedIPv4(ip); ok {
		ip = embedded
	}
	switch {
	case !isDisallowedIP(ip):
		return classPublic
	case ip.IsLoopback():
		return classLoopback
	case ip.Is4() && (ip.IsPrivate() || isSharedAddressSpace(ip)):
		return classPrivate
	case ip.Is6() && ip.As16()[0]&0xfe == 0xfc:
		return classPrivate
	}
	return classBlocked
}

func isSharedAddressSpace(ip netip.Addr) bool {
	octets := ip.As4()
	return octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127
}

// addressPolicy decides which addresses a connection of the OAuth client may
// reach. Public addresses are always fine. A loopback or private address is
// fine only when the resource itself is of that class.
type addressPolicy struct {
	baseIP      netip.Addr
	baseClasses []addressClass
}

func newAddressPolicy(base *url.URL) addressPolicy {
	host := base.Hostname()
	ip, err := netip.ParseAddr(host)
	if err == nil {
		return addressPolicy{baseIP: ip, baseClasses: []addressClass{classOf(ip)}}
	}
	if isLoopbackName(host) {
		return addressPolicy{baseClasses: []addressClass{classLoopback}}
	}
	return addressPolicy{}
}

func (p addressPolicy) allows(ip netip.Addr) bool {
	if p.baseIP.IsValid() && p.baseIP == ip {
		return true
	}
	class := classOf(ip)
	switch class {
	case classPublic:
		return true
	case classLoopback, classPrivate:
		for _, allowed := range p.baseClasses {
			if allowed == class {
				return true
			}
		}
	}
	return false
}

// control is the dialer hook that checks the address a connection really goes
// to, after DNS. A name that the resource controls cannot be rebound to an
// internal address this way.
func (p addressPolicy) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || p.allows(ip) {
		return err
	}
	return &net.AddrError{Err: "address not allowed for OAuth requests from this resource", Addr: address}
}
