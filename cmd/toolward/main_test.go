package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/testing/fakeupstream"
)

// processWait bounds a wedged binary rather than pacing the tests; generous so
// a loaded machine never reaches it.
const processWait = 30 * time.Second

var toolwardBinary string

// coverDir is where a `-cover` binary writes its profile; empty means the
// binary is built plain.
var coverDir = os.Getenv("TOOLWARD_COVERDIR")

func TestMain(m *testing.M) {
	// serve tests run this test binary as the fake upstream.
	if os.Getenv(fakeupstream.EnvSwitch) == "1" {
		fakeupstream.Run()
		return
	}
	os.Exit(buildAndRun(m))
}

// buildAndRun builds the binary once, so every binary test drives the real thing.
func buildAndRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "toolward-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	toolwardBinary = filepath.Join(dir, "toolward")
	buildArgs := []string{"build", "-mod=vendor"}
	if coverDir != "" {
		if err := os.MkdirAll(coverDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		buildArgs = append(buildArgs, "-cover", "-coverpkg=github.com/henry40408/toolward/...")
	}
	build := exec.Command("go", append(buildArgs, "-o", toolwardBinary, ".")...)
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build failed: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

func toolwardCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, toolwardBinary, args...)
	// No HOME and no XDG_CONFIG_HOME: a test that forgets --config must fail
	// instead of reading the config of the developer.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}
	return cmd
}

func runToCompletion(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), processWait)
	defer cancel()
	cmd := toolwardCommand(ctx, args...)
	var out, errw bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errw
	if err := cmd.Run(); err != nil && cmd.ProcessState == nil {
		t.Fatalf("failed to run toolward: %v", err)
	}
	return out.String(), errw.String(), cmd.ProcessState.ExitCode()
}

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHelpListsTheCommands(t *testing.T) {
	stdout, stderr, code := runToCompletion(t, "--help")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, name := range []string{"serve", "check", "import", "secret set", "auth login"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("help lacks %q: %s", name, stdout)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	stdout, stderr, code := runToCompletion(t, "--version")
	if code != 0 || stderr != "" || !strings.HasPrefix(stdout, "toolward ") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestUsageErrorsExitWithTwo(t *testing.T) {
	cases := [][]string{
		{},
		{"nonsense"},
		{"secret"},
		{"secret", "set"},
		{"check", "--format", "xml"},
		{"check", "extra"},
		{"--bogus", "check"},
	}
	for _, args := range cases {
		stdout, stderr, code := runToCompletion(t, args...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "error: ") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestCheckOfAConfigWithoutSecretsPasses(t *testing.T) {
	config := writeConfig(t, `{"mcpServers":{"plain":{"command":"x"}}}`)
	stdout, stderr, code := runToCompletion(t, "--config", config, "check")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "plain") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestAMissingConfigIsAnErrorWithExitOne(t *testing.T) {
	_, stderr, code := runToCompletion(t, "check", "--config", filepath.Join(t.TempDir(), "nope.json"))
	if code != 1 || !strings.HasPrefix(stderr, "error: cannot read ") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
