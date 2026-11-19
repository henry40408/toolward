package check

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"unicode"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/names"
	"github.com/henry40408/toolward/internal/proxy"
	"github.com/henry40408/toolward/internal/upstream"
)

// CheckTools connects to every upstream one after another and adds what each
// announced (protocol version, server, capabilities) and the tool names the
// agent will see. It shuts the upstreams down at the end. A report is added
// for an upstream that has none yet.
func CheckTools(ctx context.Context, p *proxy.Proxy, reports []*ServerReport) []*ServerReport {
	for _, u := range p.Upstreams() {
		var report *ServerReport
		reports, report = reportFor(reports, u.Name())
		report.Upstream = checkUpstream(ctx, u)
	}
	p.Shutdown()
	return reports
}

func reportFor(reports []*ServerReport, name string) ([]*ServerReport, *ServerReport) {
	for _, report := range reports {
		if report.Name == name {
			return reports, report
		}
	}
	report := newServerReport(name)
	return append(reports, report), report
}

func checkUpstream(ctx context.Context, u *upstream.Upstream) *UpstreamReport {
	if _, err := u.Tools(ctx); err != nil {
		return &UpstreamReport{Failed: true, Reason: u.Redact(err.Error())}
	}
	// A peer that went away between the two calls leaves nothing to announce.
	session, err := u.ListPeer(ctx)
	if err != nil {
		session = nil
	}
	return announced(u, session)
}

func announced(u *upstream.Upstream, session *mcpwire.Session) *UpstreamReport {
	report := &UpstreamReport{Capabilities: []string{}, Tools: toolReports(u)}
	if session == nil {
		return report
	}
	info := session.Info
	protocol := u.Redact(info.ProtocolVersion)
	report.Protocol = &protocol
	if info.ServerInfo.Name != "" || info.ServerInfo.Version != "" {
		// Server text must not start a line of its own.
		server := u.Redact(replaceControls(info.ServerInfo.Name + " " + info.ServerInfo.Version))
		report.Server = &server
	}
	for _, name := range capabilityNames(info.Capabilities) {
		report.Capabilities = append(report.Capabilities, u.Redact(name))
	}
	return report
}

func replaceControls(text string) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsControl(char) {
			return '?'
		}
		return char
	}, text)
}

func toolReports(u *upstream.Upstream) []ToolReport {
	tools := []ToolReport{}
	for _, tool := range u.ToolNames() {
		tools = append(tools, ToolReport{Name: u.Name() + names.Separator + tool.Exposed, Original: tool.Original})
	}
	return tools
}

// capabilityNames returns the capabilities and extensions a server declares,
// such as `tools` or `io.modelcontextprotocol/tasks`, sorted by name.
func capabilityNames(capabilities json.RawMessage) []string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(capabilities, &fields) != nil {
		return nil
	}
	var found []string
	for key, value := range fields {
		found = append(found, namesOfCapability(key, value)...)
	}
	slices.Sort(found)
	return found
}

func namesOfCapability(key string, value json.RawMessage) []string {
	if string(value) == "null" {
		return nil
	}
	var extensions map[string]json.RawMessage
	if key != "extensions" || json.Unmarshal(value, &extensions) != nil {
		return []string{key}
	}
	extensionNames := make([]string, 0, len(extensions))
	for name := range extensions {
		extensionNames = append(extensionNames, name)
	}
	return extensionNames
}
