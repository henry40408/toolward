package check

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/henry40408/toolward/internal/names"
)

const (
	green = "\x1b[32m"
	red   = "\x1b[31m"
	dim   = "\x1b[2m"
	reset = "\x1b[0m"
)

// paint wraps text in an ANSI color when color is on.
func paint(color bool, code, text string) string {
	if !color {
		return text
	}
	return code + text + reset
}

// WantsColor says whether to color the report: only on a terminal, and not
// when the user set NO_COLOR (https://no-color.org). An empty NO_COLOR counts
// as unset.
func WantsColor(stdoutIsTerminal bool, noColor string) bool {
	return stdoutIsTerminal && noColor == ""
}

// finding is one line of the text report: what was checked and how it went.
type finding struct {
	ok   bool
	text string
	// fix is a command that solves the problem, or empty.
	fix string
}

func okFinding(text string) finding {
	return finding{ok: true, text: text}
}

func problem(text, fix string) finding {
	return finding{text: text, fix: fix}
}

func findings(report *ServerReport) []finding {
	var found []finding
	if len(report.Secrets) == 0 {
		found = append(found, okFinding("no secret references"))
	}
	if report.OAuth != nil {
		found = append(found, oauthFinding(report.Name, report.OAuth))
	}
	for _, secret := range report.Secrets {
		found = append(found, secretFinding(secret))
	}
	return append(found, upstreamFindings(report.Upstream)...)
}

func upstreamFindings(upstream *UpstreamReport) []finding {
	switch {
	case upstream == nil:
		return nil
	case upstream.Failed:
		return []finding{problem("tools unavailable: "+upstream.Reason, "")}
	}
	var found []finding
	if upstream.Protocol != nil {
		found = append(found, okFinding(announcement(upstream)))
	}
	count := len(upstream.Tools)
	return append(found, okFinding(fmt.Sprintf("%d %s", count, plural(count, "tool", "tools"))))
}

func oauthFinding(server string, oauth *OAuthReport) finding {
	switch oauth.Status {
	case OAuthLoggedIn:
		return okFinding("oauth logged in")
	case OAuthNotLoggedIn:
		return problem("oauth not logged in", "toolward auth login "+server)
	}
	return problem("oauth error: "+oauth.Reason, "")
}

func secretFinding(secret SecretReport) finding {
	switch secret.Status {
	case SecretOK:
		return okFinding(secret.Account)
	case SecretMissing:
		return problem(secret.Account+" missing", "toolward secret set "+secret.Account)
	}
	return problem(secret.Account+" error: "+secret.Reason, "")
}

// announcement is what a server announced, on one line.
func announcement(upstream *UpstreamReport) string {
	parts := []string{"protocol " + *upstream.Protocol}
	if upstream.Server != nil {
		parts = append(parts, *upstream.Server)
	}
	capabilities := "(none)"
	if len(upstream.Capabilities) > 0 {
		capabilities = strings.Join(upstream.Capabilities, ", ")
	}
	return strings.Join(append(parts, capabilities), " · ")
}

// toolLines returns the tool names of a server, marking those that were
// renamed.
func toolLines(report *ServerReport) []string {
	if report.Upstream == nil || report.Upstream.Failed {
		return nil
	}
	lines := make([]string, 0, len(report.Upstream.Tools))
	for _, tool := range report.Upstream.Tools {
		if tool.Name == report.Name+names.Separator+tool.Original {
			lines = append(lines, tool.Name)
			continue
		}
		lines = append(lines, fmt.Sprintf("%s  (renamed from %s)", tool.Name, strconv.Quote(tool.Original)))
	}
	return lines
}

// TextOptions tells RenderText what to print.
type TextOptions struct {
	// ToolsChecked tells whether CheckTools ran.
	ToolsChecked bool
	// Color adds ANSI colors to the marks and the fix lines.
	Color bool
}

// RenderText prints one block per server and a summary line.
func RenderText(out io.Writer, reports []*ServerReport, options TextOptions) error {
	var text strings.Builder
	for _, report := range reports {
		writeBlock(&text, report, options.Color)
	}
	text.WriteString(summary(reports, options.ToolsChecked))
	text.WriteString("\n")
	_, err := io.WriteString(out, text.String())
	return err
}

func writeBlock(text *strings.Builder, report *ServerReport, color bool) {
	text.WriteString(report.Name + "\n")
	for _, found := range findings(report) {
		mark := paint(color, green, "✓")
		if !found.ok {
			mark = paint(color, red, "✗")
		}
		fmt.Fprintf(text, "  %s %s\n", mark, found.text)
		if found.fix != "" {
			fmt.Fprintf(text, "      %s\n", paint(color, dim, "fix: "+found.fix))
		}
	}
	for _, tool := range toolLines(report) {
		fmt.Fprintf(text, "      %s\n", tool)
	}
	text.WriteString("\n")
}

func summary(reports []*ServerReport, toolsChecked bool) string {
	total := len(reports)
	withProblems := 0
	for _, report := range reports {
		if !report.OK() {
			withProblems++
		}
	}
	servers := plural(total, "server", "servers")
	line := fmt.Sprintf("%d %s, all ok", total, servers)
	if withProblems > 0 {
		line = fmt.Sprintf("%d %s, %d with %s", total, servers, withProblems, plural(withProblems, "problem", "problems"))
	}
	if !toolsChecked {
		line += " (run with --tools to also connect)"
	}
	return line
}

func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}
