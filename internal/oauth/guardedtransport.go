package oauth

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

// newGuardedTransport returns a transport that enforces the addressPolicy in
// every setup, with or without a proxy:
//   - a connection the client makes itself (no proxy, or a NO_PROXY target)
//     is checked after DNS;
//   - the proxy host is the one name exempt from that check, because the
//     operator chose it;
//   - a request to an IP literal is checked before it is sent, on redirects
//     too, because a proxy would resolve nothing and hide the address.
//
// A host name that goes through a proxy is resolved by the proxy, so only the
// proxy can refuse it.
func newGuardedTransport(base *url.URL, proxies *httpproxy.Config) http.RoundTripper {
	policy := newAddressPolicy(base)
	proxyFor := proxies.ProxyFunc()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(request *http.Request) (*url.URL, error) { return proxyFor(request.URL) }
	transport.DialContext = guardedDial(policy, proxyAddresses(proxies))
	return literalGuard{policy: policy, next: transport}
}

func guardedDial(policy addressPolicy, exempt map[string]bool) func(context.Context, string, string) (net.Conn, error) {
	checked := &net.Dialer{Timeout: oauthHTTPTimeout, Control: policy.control}
	plain := &net.Dialer{Timeout: oauthHTTPTimeout}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if exempt[strings.ToLower(address)] {
			return plain.DialContext(ctx, network, address)
		}
		return checked.DialContext(ctx, network, address)
	}
}

// proxyAddresses lists the host:port pairs the transport dials for the
// proxies of the environment.
func proxyAddresses(proxies *httpproxy.Config) map[string]bool {
	addresses := map[string]bool{}
	for _, raw := range []string{proxies.HTTPProxy, proxies.HTTPSProxy} {
		if address, ok := proxyAddress(raw); ok {
			addresses[address] = true
		}
	}
	return addresses
}

func proxyAddress(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		parsed, err = url.Parse("http://" + raw)
	}
	if err != nil || parsed.Hostname() == "" {
		return "", false
	}
	port := parsed.Port()
	if port == "" {
		port = defaultProxyPort(parsed.Scheme)
	}
	return net.JoinHostPort(strings.ToLower(parsed.Hostname()), port), true
}

func defaultProxyPort(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "socks5", "socks5h":
		return "1080"
	}
	return "80"
}

// literalGuard refuses a request whose URL names a forbidden IP address.
type literalGuard struct {
	policy addressPolicy
	next   http.RoundTripper
}

func (g literalGuard) RoundTrip(request *http.Request) (*http.Response, error) {
	host := request.URL.Hostname()
	ip, err := netip.ParseAddr(host)
	if err == nil && !g.policy.allows(ip) {
		return nil, &net.AddrError{Err: "address not allowed for OAuth requests from this resource", Addr: ip.String()}
	}
	if err != nil && looksNumeric(host) {
		return nil, &net.AddrError{Err: "numeric host not allowed for OAuth requests from this resource", Addr: host}
	}
	return g.next.RoundTrip(request)
}

// looksNumeric reports a host whose last label is all digits or a hex number,
// such as 2130706433, 0x7f000001 or 127.1. A proxy may read these as IPv4
// addresses (inet_aton) that netip does not parse.
func looksNumeric(host string) bool {
	host = strings.TrimSuffix(host, ".")
	label := host[strings.LastIndex(host, ".")+1:]
	if label == "" {
		return false
	}
	digits := label
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	if rest := strings.TrimPrefix(strings.ToLower(label), "0x"); rest != strings.ToLower(label) {
		digits = rest
		isDigit = func(r rune) bool { return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' }
	}
	return digits == "" || strings.IndexFunc(digits, func(r rune) bool { return !isDigit(r) }) < 0
}
