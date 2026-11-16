// Package interpolate expands "${keychain:<account>}" references in config strings.
//
//   - "${keychain:name}" is replaced with the secret stored under name.
//   - "$${" is an escape for a literal "${".
//   - Any other "${...}" is rejected so typos never reach an upstream verbatim.
package interpolate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/henry40408/toolward/internal/store"
)

// The messages never quote the config text: it may already contain a literal secret.
var (
	ErrUnterminated = errors.New("unterminated '${' reference")
	ErrUnsupported  = errors.New("unsupported '${...}' reference: only '${keychain:<account>}' is supported")
)

// MissingError reports a reference to an account that has no secret.
type MissingError struct{ Account string }

func (e *MissingError) Error() string {
	return fmt.Sprintf("no secret stored for account %q; run `toolward secret set %s`", e.Account, e.Account)
}

type segment struct {
	literal string
	account string // set for a keychain reference
}

func (s segment) isReference() bool { return s.account != "" }

func parse(input string) ([]segment, error) {
	var segments []segment
	var literal strings.Builder
	rest := input
	for {
		pos := strings.IndexByte(rest, '$')
		if pos < 0 {
			break
		}
		literal.WriteString(rest[:pos])
		rest = rest[pos:]
		if after, ok := strings.CutPrefix(rest, "$${"); ok {
			literal.WriteString("${")
			rest = after
			continue
		}
		after, ok := strings.CutPrefix(rest, "${")
		if !ok {
			literal.WriteByte('$')
			rest = rest[1:]
			continue
		}
		account, remainder, err := parseReference(after)
		if err != nil {
			return nil, err
		}
		if literal.Len() > 0 {
			segments = append(segments, segment{literal: literal.String()})
			literal.Reset()
		}
		segments = append(segments, segment{account: account})
		rest = remainder
	}
	literal.WriteString(rest)
	if literal.Len() > 0 {
		segments = append(segments, segment{literal: literal.String()})
	}
	return segments, nil
}

// parseReference reads the text after "${" and returns the account and what follows the "}".
func parseReference(afterOpen string) (account, remainder string, err error) {
	end := strings.IndexByte(afterOpen, '}')
	if end < 0 {
		return "", "", ErrUnterminated
	}
	account, ok := strings.CutPrefix(afterOpen[:end], "keychain:")
	if !ok {
		return "", "", ErrUnsupported
	}
	if err := store.ValidateUserAccount(account); err != nil {
		return "", "", err
	}
	return account, afterOpen[end+1:], nil
}

// References lists the accounts referenced by input, in order of appearance.
func References(input string) ([]string, error) {
	segments, err := parse(input)
	if err != nil {
		return nil, err
	}
	var accounts []string
	for _, s := range segments {
		if s.isReference() {
			accounts = append(accounts, s.account)
		}
	}
	return accounts, nil
}

// Expand expands every reference in input using s.
func Expand(input string, s store.Store) (string, error) {
	out, _, err := ExpandCollecting(input, s)
	return out, err
}

// ExpandCollecting is like Expand, and also returns every secret value it
// substituted, so callers can redact those values from output later. On an
// error it returns the secrets read before the failure.
func ExpandCollecting(input string, s store.Store) (string, []string, error) {
	segments, err := parse(input)
	if err != nil {
		return "", nil, err
	}
	var out strings.Builder
	var secrets []string
	for _, seg := range segments {
		if !seg.isReference() {
			out.WriteString(seg.literal)
			continue
		}
		secret, found, err := s.Get(seg.account)
		if err != nil {
			return "", secrets, err
		}
		if !found {
			return "", secrets, &MissingError{Account: seg.account}
		}
		out.WriteString(secret)
		secrets = append(secrets, secret)
	}
	return out.String(), secrets, nil
}
