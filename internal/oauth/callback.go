package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	requestReadTimeout  = 5 * time.Second
	maxRequestBytes     = 8192
	maxErrorCodeLength  = 40
	callbackPath        = "/callback"
	callbackLoopbackIP  = "127.0.0.1"
	loggedInPageMessage = "Logged in to toolward. You can close this tab."
)

// Callback is the loopback server that receives the redirect of the browser.
// It is bound before registration, because the redirect URI must be known
// then.
type Callback struct {
	listener net.Listener
	port     int
	// readTimeout bounds the wait for a request line. Tests shorten it.
	readTimeout time.Duration
}

// ListenCallback binds 127.0.0.1:port. Port 0 picks a free one.
func ListenCallback(port uint16) (*Callback, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(callbackLoopbackIP, strconv.Itoa(int(port))))
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s:%d: %w", callbackLoopbackIP, port, err)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("the callback listener has no TCP address")
	}
	return &Callback{listener: listener, port: address.Port, readTimeout: requestReadTimeout}, nil
}

// Close stops listening.
func (c *Callback) Close() error { return c.listener.Close() }

// Port is the port the server listens on.
func (c *Callback) Port() int { return c.port }

// RedirectURI is the redirect URI to register and to send.
func (c *Callback) RedirectURI() string {
	return fmt.Sprintf("http://%s:%d%s", callbackLoopbackIP, c.port, callbackPath)
}

// Wait accepts connections until one carries the OAuth redirect, and returns
// its URL. Anything else (favicon requests, port scans) is answered and
// ignored. A redirect with an error ends the wait with a failure that holds
// only the short error code.
func (c *Callback) Wait(ctx context.Context, expectedState string) (string, error) {
	stop := context.AfterFunc(ctx, func() { _ = c.listener.Close() })
	defer stop()
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", err
		}
		redirect, done, err := c.serve(conn, expectedState)
		if done {
			return redirect, err
		}
	}
}

// serve answers one connection. done is true when the wait is over.
func (c *Callback) serve(conn net.Conn, expectedState string) (redirect string, done bool, err error) {
	defer conn.Close()
	target, ok := readRequestTarget(conn, c.readTimeout)
	if !ok {
		respond(conn, "400 Bad Request", "Bad request")
		return "", false, nil
	}
	if !strings.HasPrefix(target, callbackPath+"?") {
		respond(conn, "404 Not Found", "Not found")
		return "", false, nil
	}
	redirect = fmt.Sprintf("http://%s:%d%s", callbackLoopbackIP, c.port, target)
	parsed, err := url.Parse(redirect)
	if err != nil {
		return "", true, errors.New("the callback URL is invalid")
	}
	return c.answer(conn, parsed, expectedState)
}

func (c *Callback) answer(conn net.Conn, redirect *url.URL, expectedState string) (string, bool, error) {
	query := redirect.Query()
	if !slices.Contains(query["state"], expectedState) {
		respond(conn, "400 Bad Request", "Unexpected request")
		return "", false, nil
	}
	if codes := query["error"]; len(codes) > 0 {
		respond(conn, "400 Bad Request", "Authorization failed. You can close this tab.")
		return "", true, fmt.Errorf("the server refused the authorization (%s)", shortErrorCode(codes[len(codes)-1]))
	}
	if !query.Has("code") {
		respond(conn, "400 Bad Request", "Missing code")
		return "", false, nil
	}
	respond(conn, "200 OK", loggedInPageMessage)
	return redirect.String(), true, nil
}

// shortErrorCode keeps the letters, digits and underscores of an error code.
// Descriptions are server text and never shown.
func shortErrorCode(code string) string {
	var kept strings.Builder
	count := 0
	for _, char := range code {
		if count == maxErrorCodeLength {
			break
		}
		if isCodeRune(char) {
			kept.WriteRune(char)
			count++
		}
	}
	return kept.String()
}

func isCodeRune(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_'
}

// readRequestTarget returns the target of a GET request. It is false for any
// other request, for a request line that does not arrive in time, and for a
// connection that closes first.
func readRequestTarget(conn net.Conn, timeout time.Duration) (string, bool) {
	if conn.SetReadDeadline(time.Now().Add(timeout)) != nil {
		return "", false
	}
	buffer := make([]byte, maxRequestBytes)
	length := 0
	for {
		n, err := conn.Read(buffer[length:])
		length += n
		if bytes.Contains(buffer[:length], []byte("\r\n")) || length == len(buffer) {
			break
		}
		if err != nil || n == 0 {
			return "", false
		}
	}
	return parseRequestLine(string(bytes.ToValidUTF8(buffer[:length], []byte("�"))))
}

func parseRequestLine(text string) (string, bool) {
	line, _, _ := strings.Cut(text, "\n")
	line = strings.TrimSuffix(line, "\r")
	parts := strings.Split(line, " ")
	if len(parts) < 2 || parts[0] != "GET" {
		return "", false
	}
	return parts[1], true
}

func respond(conn net.Conn, status, body string) {
	reply := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, len(body), body)
	_, _ = conn.Write([]byte(reply))
}
