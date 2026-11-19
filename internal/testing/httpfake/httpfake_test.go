package httpfake

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func post(t *testing.T, fake *Fake, body string, header http.Header) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, fake.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for key, values := range header {
		request.Header[key] = values
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data)
}

func rpc(method, params string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `}`
}

func TestInitializeRecordsTheOfferedVersion(t *testing.T) {
	fake := New(t)
	status, body := post(t, fake, rpc("initialize", `{"protocolVersion":"2025-11-25"}`), nil)
	if status != 200 || !strings.Contains(body, `"fake-http"`) || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
		t.Errorf("answer = %d %s", status, body)
	}
	if got := fake.Versions(); !slices.Equal(got, []string{"2025-11-25"}) {
		t.Errorf("versions = %v", got)
	}
}

func TestToolsAreConfigurable(t *testing.T) {
	fake := New(t, "a", "b")
	_, body := post(t, fake, rpc("tools/list", `{}`), nil)
	if !strings.Contains(body, `"name":"a"`) || !strings.Contains(body, `"name":"b"`) {
		t.Errorf("list = %s", body)
	}
	fake.SetTools("c")
	_, body = post(t, fake, rpc("tools/list", `{}`), nil)
	if strings.Contains(body, `"name":"a"`) || !strings.Contains(body, `"name":"c"`) {
		t.Errorf("list = %s", body)
	}
}

func TestWhoamiEchoesTheAuthorizationHeader(t *testing.T) {
	fake := New(t)
	_, body := post(t, fake, rpc("tools/call", `{"name":"whoami"}`), http.Header{"Authorization": {"Bearer abc"}})
	if !strings.Contains(body, `"text":"Bearer abc"`) {
		t.Errorf("body = %s", body)
	}
	if got := fake.Authorizations(); !slices.Equal(got, []string{"Bearer abc"}) {
		t.Errorf("authorizations = %v", got)
	}
}

func TestResourcesAndPrompts(t *testing.T) {
	fake := New(t)
	_, listed := post(t, fake, rpc("resources/list", `{}`), nil)
	if !strings.Contains(listed, `file:///a b/notes.txt?x=1`) {
		t.Errorf("resources = %s", listed)
	}
	_, read := post(t, fake, rpc("resources/read", `{"uri":"file:///x"}`), http.Header{"Authorization": {"K"}})
	if !strings.Contains(read, `"uri":"file:///x"`) || !strings.Contains(read, `helloK`) {
		t.Errorf("read = %s", read)
	}
	_, prompt := post(t, fake, rpc("prompts/get", `{"name":"greet"}`), http.Header{"Authorization": {"K"}})
	if !strings.Contains(prompt, `prompt greetK`) {
		t.Errorf("prompt = %s", prompt)
	}
}

func TestDiscoverIsMethodNotFoundOrAConfiguredStatus(t *testing.T) {
	fake := New(t)
	status, body := post(t, fake, rpc("server/discover", `{}`), nil)
	if status != 200 || !strings.Contains(body, `-32601`) {
		t.Errorf("answer = %d %s", status, body)
	}
	fake.DiscoverStatus(500)
	if status, _ := post(t, fake, rpc("server/discover", `{}`), nil); status != 500 {
		t.Errorf("status = %d", status)
	}
}

func TestNotificationsGet202AndOtherVerbsGet405(t *testing.T) {
	fake := New(t)
	status, _ := post(t, fake, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	if status != http.StatusAccepted {
		t.Errorf("notification status = %d", status)
	}
	response, err := http.Get(fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", response.StatusCode)
	}
}

func TestFailWithRejectsEverythingAndEchoesTheHeader(t *testing.T) {
	fake := New(t)
	fake.FailWith(500)
	status, body := post(t, fake, rpc("initialize", `{}`), http.Header{"Authorization": {"Bearer abc"}})
	if status != 500 || body != "rejected Bearer abc" {
		t.Errorf("answer = %d %q", status, body)
	}
	fake.FailWith(0)
	if status, _ := post(t, fake, rpc("tools/list", `{}`), nil); status != 200 {
		t.Errorf("status after reset = %d", status)
	}
}

func TestRequestsRecordTheHeaders(t *testing.T) {
	fake := New(t)
	post(t, fake, rpc("ping", `{}`), http.Header{"Mcp-Protocol-Version": {"2025-11-25"}})
	requests := fake.Requests()
	if len(requests) != 1 || requests[0].Method != "POST" || requests[0].Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
		t.Errorf("requests = %+v", requests)
	}
}

func TestSilentNeverAnswers(t *testing.T) {
	fake := NewSilent(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, fake.URL, strings.NewReader(rpc("ping", `{}`)))
	if response, err := http.DefaultClient.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("a silent fake answered")
	}
	if len(fake.Requests()) != 1 {
		t.Errorf("requests = %d", len(fake.Requests()))
	}
}
