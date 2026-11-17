package importer

import (
	"fmt"
	"io"
	"strings"
)

// Report prints the plan. It never prints a secret value.
func Report(plan *Plan, applied bool, out io.Writer) error {
	verb := "would move"
	if applied {
		verb = "moved"
	}
	var text strings.Builder
	for _, moved := range plan.Moves {
		fmt.Fprintf(&text, "%s %s: %s -> ${keychain:%s}\n", verb, moved.Server, moved.Place, moved.Account)
	}
	if len(plan.Moves) == 0 {
		text.WriteString("no secret-looking env or header values found\n")
	}
	for _, line := range plan.Skipped {
		fmt.Fprintf(&text, "skipped %s\n", line)
	}
	for _, line := range plan.Notes {
		fmt.Fprintf(&text, "note: %s\n", line)
	}
	text.WriteString(closing(applied))
	_, err := io.WriteString(out, text.String())
	return err
}

func closing(applied bool) string {
	if applied {
		return "\nNext: replace the servers in your mcp.json with one entry that runs " +
			"`toolward serve`, and rotate the tokens that were in that file.\n"
	}
	return "\nNote: with --apply, an account name gets a numeric suffix (-2, -3, ...) " +
		"if that name already holds a different value.\n" +
		"\nNothing was changed. Run again with --apply to do it.\n"
}
