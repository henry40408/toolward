package upstream

import (
	"slices"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/store"
)

func TestBuildHeadersResolvesSecretsAndReportsThem(t *testing.T) {
	secrets := store.NewMemoryWith(map[string]string{"tok": "s3cr3t"})

	built, err := BuildHeaders(map[string]string{"authorization": "Bearer ${keychain:tok}", "X-Plain": "v"}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got := built.Header.Get("Authorization"); got != "Bearer s3cr3t" {
		t.Errorf("Authorization = %q", got)
	}
	if got := built.Header.Get("X-Plain"); got != "v" {
		t.Errorf("X-Plain = %q", got)
	}
	if !slices.Equal(built.Secrets, []string{"s3cr3t"}) {
		t.Errorf("secrets = %v", built.Secrets)
	}
}

func TestBuildHeadersErrors(t *testing.T) {
	secrets := store.NewMemoryWith(map[string]string{"tok": "s3cr3t"})
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"invalid name", map[string]string{"bad name": "v"}, `invalid header name "bad name"`},
		{"empty name", map[string]string{"": "v"}, `invalid header name ""`},
		{"invalid value", map[string]string{"X": "line\nbreak"}, `invalid value for header "X"`},
		{"duplicate ignoring case", map[string]string{"X-Key": "a", "x-key": "b"}, `header "x-key" is set twice (names ignore case)`},
		{"missing secret", map[string]string{"X": "${keychain:absent}"}, "absent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildHeaders(test.headers, secrets)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestBuildHeadersNeverEchoesAValueInAnError(t *testing.T) {
	secrets := store.NewMemoryWith(map[string]string{"tok": "s3cr3t"})

	_, err := BuildHeaders(map[string]string{"X": "${keychain:tok}\n"}, secrets)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("err = %v", err)
	}
}
