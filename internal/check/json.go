package check

import (
	"encoding/json"
	"io"
)

type jsonReport struct {
	OK      bool         `json:"ok"`
	Servers []jsonServer `json:"servers"`
}

type jsonServer struct {
	Name     string         `json:"name"`
	OK       bool           `json:"ok"`
	Secrets  []SecretReport `json:"secrets"`
	OAuth    *OAuthReport   `json:"oauth"`
	Upstream any            `json:"upstream"`
}

type jsonUpstreamFailed struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type jsonUpstreamOK struct {
	Status       string       `json:"status"`
	Protocol     *string      `json:"protocol"`
	Server       *string      `json:"server"`
	Capabilities []string     `json:"capabilities"`
	Tools        []ToolReport `json:"tools"`
}

// jsonUpstreamOf gives the shape of an UpstreamReport on the wire: the status
// decides which of the other fields are present.
func jsonUpstreamOf(report *UpstreamReport) any {
	if report == nil {
		return nil
	}
	if report.Failed {
		return jsonUpstreamFailed{Status: "error", Reason: report.Reason}
	}
	ok := jsonUpstreamOK{Status: "ok", Protocol: report.Protocol, Server: report.Server, Capabilities: report.Capabilities, Tools: report.Tools}
	if ok.Capabilities == nil {
		ok.Capabilities = []string{}
	}
	if ok.Tools == nil {
		ok.Tools = []ToolReport{}
	}
	return ok
}

// RenderJSON prints the facts as one JSON object on one line. It is never
// colored.
func RenderJSON(out io.Writer, reports []*ServerReport) error {
	document := jsonReport{OK: AllOK(reports), Servers: make([]jsonServer, 0, len(reports))}
	for _, report := range reports {
		document.Servers = append(document.Servers, jsonServerOf(report))
	}
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

func jsonServerOf(report *ServerReport) jsonServer {
	server := jsonServer{Name: report.Name, OK: report.OK(), Secrets: report.Secrets, OAuth: report.OAuth, Upstream: jsonUpstreamOf(report.Upstream)}
	if server.Secrets == nil {
		server.Secrets = []SecretReport{}
	}
	return server
}
