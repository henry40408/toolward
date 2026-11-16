// Command toolward is an MCP proxy that keeps credentials out of the config
// files an agent can read.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/version"
)

const (
	exitFailure = 1
	exitUsage   = 2
)

// process is everything run needs from the outside world.
type process struct {
	args      []string
	lookupEnv func(string) (string, bool)
	stdin     *os.File
	stdout    io.Writer
	stderr    io.Writer
	// stdoutIsTerminal decides the color of the check report.
	stdoutIsTerminal bool
	// newStore opens the credential store. Only the real program uses the
	// Keychain; tests pass an in-memory store.
	newStore func() (store.Store, error)
}

func main() {
	os.Exit(run(process{
		args:             os.Args[1:],
		lookupEnv:        os.LookupEnv,
		stdin:            os.Stdin,
		stdout:           os.Stdout,
		stderr:           os.Stderr,
		stdoutIsTerminal: term.IsTerminal(int(os.Stdout.Fd())),
		newStore:         store.NewKeychain,
	}))
}

// errCheckFailed makes the exit code 1 without a message: the report already
// said what is wrong.
var errCheckFailed = errors.New("check failed")

// run returns the exit code.
func run(p process) int {
	invocation, err := parseInvocation(p.args)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.WriteString(p.stdout, invocation.helpText)
		return 0
	}
	if err != nil {
		return reportFatal(p.stderr, err)
	}
	if invocation.showVersion {
		_, _ = fmt.Fprintf(p.stdout, "toolward %s\n", version.Version())
		return 0
	}
	err = invocation.command.run(p, invocation)
	if errors.Is(err, errCheckFailed) {
		return exitFailure
	}
	if err != nil {
		return reportFatal(p.stderr, err)
	}
	return 0
}

func reportFatal(stderr io.Writer, err error) int {
	var usage usageError
	if errors.As(err, &usage) {
		_, _ = fmt.Fprintf(stderr, "error: %v\n\nFor more information, try '--help'.\n", err)
		return exitUsage
	}
	_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
	return exitFailure
}
