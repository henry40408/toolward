package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"

	"github.com/henry40408/toolward/internal/store"
)

func runSecretSet(p process, inv *invocation) error {
	account := inv.argument(0)
	// Fail before prompting, so the user does not type a secret for a rejected name.
	if err := store.ValidateUserAccount(account); err != nil {
		return err
	}
	credentials, err := p.newStore()
	if err != nil {
		return err
	}
	secret, err := readSecret(p, account)
	if err != nil {
		return err
	}
	return secretSet(credentials, account, secret, p.stdout)
}

func secretSet(credentials store.Store, account, secret string, out io.Writer) error {
	if err := store.ValidateUserAccount(account); err != nil {
		return err
	}
	if secret == "" {
		return errors.New("refusing to store an empty secret")
	}
	if err := credentials.Set(account, secret); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "stored secret for %q\n", account)
	return err
}

func runSecretDelete(p process, inv *invocation) error {
	credentials, err := p.newStore()
	if err != nil {
		return err
	}
	return secretDelete(credentials, inv.argument(0), p.stdout)
}

func secretDelete(credentials store.Store, account string, out io.Writer) error {
	existed, err := credentials.Delete(account)
	if err != nil {
		return err
	}
	if existed {
		_, err = fmt.Fprintf(out, "deleted secret for %q\n", account)
	} else {
		_, err = fmt.Fprintf(out, "no secret stored for %q\n", account)
	}
	return err
}

// readSecret reads the secret from a hidden prompt on a terminal, else from
// stdin. It never comes from the command line, where other users could see it.
func readSecret(p process, account string) (string, error) {
	if term.IsTerminal(int(p.stdin.Fd())) {
		return promptSecret(p, account)
	}
	// Read everything so multi-line secrets (PEM keys, JSON files) stay intact.
	text, err := io.ReadAll(p.stdin)
	if err != nil {
		return "", errors.New("cannot read the secret from stdin")
	}
	return trimOneNewline(string(text)), nil
}

func trimOneNewline(text string) string {
	text = strings.TrimSuffix(text, "\n")
	return strings.TrimSuffix(text, "\r")
}

func promptSecret(p process, account string) (string, error) {
	first, err := promptHidden(p, "Secret for "+account+": ")
	if err != nil {
		return "", err
	}
	again, err := promptHidden(p, "Repeat to confirm: ")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", errors.New("the two entries differ")
	}
	return first, nil
}

func promptHidden(p process, prompt string) (string, error) {
	_, _ = io.WriteString(p.stderr, prompt)
	secret, err := term.ReadPassword(int(p.stdin.Fd()))
	_, _ = io.WriteString(p.stderr, "\n")
	if err != nil {
		return "", err
	}
	return string(secret), nil
}
