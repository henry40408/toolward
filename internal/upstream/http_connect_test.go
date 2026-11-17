package upstream

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/testing/httpfake"
)

func connectContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newTestHandler() *Handler {
	return &Handler{hub: &Hub{}, forgetTools: func() {}}
}

func TestHTTPConnectorResolvesHeadersAndRemembersTheirSecrets(t *testing.T) {
	fake := httpfake.New(t, "echo")
	connector := &HTTPConnector{
		Spec:  HTTPSpec{URL: fake.URL, Headers: map[string]string{"Authorization": "Bearer ${keychain:tok}"}},
		Store: store.NewMemoryWith(map[string]string{"tok": "s3cr3t"}),
	}
	handler := newTestHandler()
	session, err := connector.Connect(connectContext(t), handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Peer.Close() })
	if got := handler.Secrets(); len(got) != 1 || got[0] != "s3cr3t" {
		t.Fatalf("secrets %v", got)
	}
	for _, header := range fake.Authorizations() {
		if header != "Bearer s3cr3t" {
			t.Fatalf("authorization %q", header)
		}
	}
}

func TestHTTPConnectorRefusesToConnectWithAMissingSecret(t *testing.T) {
	fake := httpfake.New(t)
	connector := &HTTPConnector{
		Spec:  HTTPSpec{URL: fake.URL, Headers: map[string]string{"X-Key": "${keychain:absent}"}},
		Store: store.NewMemory(),
	}
	if _, err := connector.Connect(connectContext(t), newTestHandler()); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("err = %v", err)
	}
	if got := len(fake.Requests()); got != 0 {
		t.Fatalf("a request was sent without its secret: %d", got)
	}
}

func TestHTTPConnectorMasksTheSecretInAHandshakeFailure(t *testing.T) {
	fake := httpfake.New(t)
	fake.FailWith(400) // the fake echoes the Authorization header in its body
	connector := &HTTPConnector{
		Spec:  HTTPSpec{URL: fake.URL, Headers: map[string]string{"Authorization": "Bearer ${keychain:tok}"}},
		Store: store.NewMemoryWith(map[string]string{"tok": "s3cr3t"}),
	}
	_, err := connector.Connect(connectContext(t), newTestHandler())
	if err == nil || !strings.HasPrefix(err.Error(), "handshake failed: ") || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("err = %v", err)
	}
}

func TestHandlerForwardsOnlyListChanges(t *testing.T) {
	forgotten := 0
	handler := &Handler{hub: &Hub{}, forgetTools: func() { forgotten++ }}
	handler.HandleNotification(context.Background(), methodToolsChanged, nil)
	handler.HandleNotification(context.Background(), methodResourcesChanged, nil)
	handler.HandleNotification(context.Background(), methodPromptsChanged, nil)
	handler.HandleNotification(context.Background(), "notifications/message", nil)
	if forgotten != 1 {
		t.Fatalf("the tool cache was dropped %d times", forgotten)
	}
}

func TestHandlerKeepsEverySecretOnce(t *testing.T) {
	handler := newTestHandler()
	handler.RememberSecrets([]string{"a"})
	handler.AddSecrets([]string{"a", "b"})
	handler.AddSecrets([]string{"b"})
	got := handler.Secrets()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("secrets %v", got)
	}
	got[0] = "changed"
	if handler.Secrets()[0] != "a" {
		t.Fatal("Secrets must return a copy")
	}
}
