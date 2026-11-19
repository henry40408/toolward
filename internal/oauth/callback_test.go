package oauth

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type waitResult struct {
	redirect string
	err      error
}

func startWait(t *testing.T, state string) (*Callback, chan waitResult, context.CancelFunc) {
	t.Helper()
	callback, err := ListenCallback(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = callback.Close() })
	callback.readTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	results := make(chan waitResult, 1)
	go func() {
		redirect, err := callback.Wait(ctx, state)
		results <- waitResult{redirect, err}
	}()
	return callback, results, cancel
}

// request sends raw bytes and returns the reply.
func request(t *testing.T, callback *Callback, raw string) string {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(callback.port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte(raw))
	reply, _ := io.ReadAll(conn)
	return string(reply)
}

func itoa(n int) string { return strconv.Itoa(n) }

func get(target string) string { return "GET " + target + " HTTP/1.1\r\nHost: x\r\n\r\n" }

func TestRedirectURIUsesTheLoopbackAddress(t *testing.T) {
	callback, _, cancel := startWait(t, "s")
	defer cancel()
	want := "http://127.0.0.1:" + itoa(callback.port) + "/callback"
	if callback.RedirectURI() != want {
		t.Fatalf("got %s", callback.RedirectURI())
	}
}

func TestTheRedirectWithTheRightStateEndsTheWait(t *testing.T) {
	callback, results, cancel := startWait(t, "s1")
	defer cancel()
	reply := request(t, callback, get("/callback?code=abc&state=s1"))
	if !strings.HasPrefix(reply, "HTTP/1.1 200 OK") {
		t.Fatalf("got %q", reply)
	}
	result := <-results
	if result.err != nil || !strings.HasSuffix(result.redirect, "/callback?code=abc&state=s1") {
		t.Fatalf("got %+v", result)
	}
}

func TestStrayRequestsAreIgnored(t *testing.T) {
	callback, results, cancel := startWait(t, "s1")
	defer cancel()
	cases := map[string]string{
		get("/favicon.ico"):                               "404",
		get("/callback?code=x&state=wrong"):               "400",
		get("/callback?state=s1"):                         "400",
		"POST /callback?code=x&state=s1 HTTP/1.1\r\n\r\n": "400",
		"garbage": "400",
	}
	for raw, status := range cases {
		if reply := request(t, callback, raw); !strings.Contains(reply, " "+status+" ") {
			t.Errorf("%q: got %q", raw, reply)
		}
	}
	select {
	case result := <-results:
		t.Fatalf("the wait must continue: %+v", result)
	default:
	}
	request(t, callback, get("/callback?code=ok&state=s1"))
	if result := <-results; result.err != nil {
		t.Fatal(result.err)
	}
}

func TestAnErrorRedirectEndsTheWaitWithOnlyTheCode(t *testing.T) {
	callback, results, cancel := startWait(t, "s1")
	defer cancel()
	request(t, callback, get("/callback?error=access_denied&error_description=SECRET+TEXT&state=s1"))
	result := <-results
	if result.err == nil || result.err.Error() != "the server refused the authorization (access_denied)" {
		t.Fatalf("got %v", result.err)
	}
}

func TestErrorCodesAreCleanedAndShortened(t *testing.T) {
	if got := shortErrorCode("a b\n<c>_9" + strings.Repeat("x", 100)); len(got) != 40 || !strings.HasPrefix(got, "abc_9x") {
		t.Fatalf("got %q", got)
	}
}

func TestAStalledConnectionDoesNotBlockTheNextOne(t *testing.T) {
	callback, results, cancel := startWait(t, "s1")
	defer cancel()
	stalled, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(callback.port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stalled.Close() }()
	time.Sleep(20 * time.Millisecond)
	request(t, callback, get("/callback?code=ok&state=s1"))
	if result := <-results; result.err != nil {
		t.Fatal(result.err)
	}
}

func TestCancelEndsTheWait(t *testing.T) {
	_, results, cancel := startWait(t, "s1")
	cancel()
	if result := <-results; result.err == nil {
		t.Fatal("the wait must fail")
	}
}
