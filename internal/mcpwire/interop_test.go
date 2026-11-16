package mcpwire

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolsMethods answers the two methods the interop tests use.
type toolsMethods struct{}

func (toolsMethods) HandleRequest(_ context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "tools/list":
		return json.RawMessage(`{"resultType":"complete","ttlMs":0,"cacheScope":"private","tools":[{"name":"echo","inputSchema":{"type":"object"}}]}`), nil
	case "tools/call":
		var call struct {
			Arguments struct {
				Text string `json:"text"`
			} `json:"arguments"`
		}
		if err := json.Unmarshal(params, &call); err != nil {
			return nil, InvalidParams(err.Error())
		}
		result, _ := json.Marshal(map[string]any{
			"resultType": "complete",
			"content":    []map[string]string{{"type": "text", "text": "echo: " + call.Arguments.Text}},
		})
		return result, nil
	}
	return nil, MethodNotFound(method)
}

func testServerConfig(onInitialized func(*Peer)) ServerConfig {
	return ServerConfig{
		Info:          Implementation{Name: "toolward", Version: "test"},
		Capabilities:  json.RawMessage(`{"tools":{"listChanged":true}}`),
		Methods:       toolsMethods{},
		OnInitialized: onInitialized,
	}
}

// goSDKPipes returns the two ends of a connection: the go-sdk transport and
// our stdio transport.
func goSDKPipes() (*mcp.IOTransport, *StdioTransport) {
	sdkRead, ourWrite := io.Pipe()
	ourRead, sdkWrite := io.Pipe()
	return &mcp.IOTransport{Reader: sdkRead, Writer: sdkWrite}, NewStdioTransport(ourRead, ourWrite)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestGoSDKClientTalksToOurServer(t *testing.T) {
	for _, version := range []string{Version20251125, Version20260728} {
		t.Run(version, func(t *testing.T) {
			ctx := testContext(t)
			sdkTransport, ours := goSDKPipes()
			peer := NewPeer(ours, NewServer(testServerConfig(nil)))
			t.Cleanup(func() { _ = peer.Close() })

			client := mcp.NewClient(&mcp.Implementation{Name: "sdk-client", Version: "1"}, nil)
			session, err := client.Connect(ctx, sdkTransport, &mcp.ClientSessionOptions{ProtocolVersion: version})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = session.Close() })

			init := session.InitializeResult()
			if init.ProtocolVersion != version {
				t.Errorf("protocol version = %q, want %q", init.ProtocolVersion, version)
			}
			if init.ServerInfo == nil || init.ServerInfo.Name != "toolward" {
				t.Errorf("server info = %+v", init.ServerInfo)
			}
			tools, err := session.ListTools(ctx, nil)
			if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "echo" {
				t.Fatalf("ListTools = %+v, %v", tools, err)
			}
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
			if err != nil {
				t.Fatal(err)
			}
			text, ok := result.Content[0].(*mcp.TextContent)
			if !ok || text.Text != "echo: hi" {
				t.Errorf("content = %+v", result.Content)
			}
		})
	}
}

func TestOurClientTalksToGoSDKServer(t *testing.T) {
	connectors := map[string]func(context.Context, *Peer, Implementation) (*Session, error){
		"initialize": Initialize,
		"discover":   Discover,
	}
	for name, connect := range connectors {
		t.Run(name, func(t *testing.T) {
			ctx := testContext(t)
			ours := startGoSDKServer(t)
			peer := NewPeer(ours, nil)
			t.Cleanup(func() { _ = peer.Close() })

			session, err := connect(ctx, peer, Implementation{Name: "toolward", Version: "test"})
			if err != nil {
				t.Fatal(err)
			}
			wantVersion := map[string]string{"initialize": Version20251125, "discover": Version20260728}[name]
			if session.Info.ProtocolVersion != wantVersion {
				t.Errorf("protocol version = %q, want %q", session.Info.ProtocolVersion, wantVersion)
			}
			if session.Info.ServerInfo.Name != "sdk-server" {
				t.Errorf("server info = %+v", session.Info.ServerInfo)
			}
			raw, err := session.Call(ctx, "tools/call", json.RawMessage(`{"name":"echo","arguments":{"text":"hi"}}`))
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Content []struct{ Text string } `json:"content"`
			}
			if err := json.Unmarshal(raw, &result); err != nil || len(result.Content) != 1 || result.Content[0].Text != "echo: hi" {
				t.Errorf("result = %s, %v", raw, err)
			}
		})
	}
}

// startGoSDKServer runs a go-sdk server and returns our end of its connection.
func startGoSDKServer(t *testing.T) *StdioTransport {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "sdk-server", Version: "2"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echoes"}, func(_ context.Context, _ *mcp.CallToolRequest, in struct {
		Text string `json:"text"`
	}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Text}}}, nil, nil
	})
	sdkTransport, ours := goSDKPipes()
	session, err := server.Connect(testContext(t), sdkTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return ours
}
