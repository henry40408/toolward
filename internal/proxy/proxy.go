// Package proxy is the MCP server the agent talks to. It exposes the tools,
// resources and prompts of every upstream under the upstream's name and
// forwards requests.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/upstream"
	"github.com/henry40408/toolward/internal/version"
)

const capabilities = `{"tools":{"listChanged":true},"resources":{"listChanged":true},"prompts":{"listChanged":true}}`

// Proxy answers the requests of the agent from its upstreams.
type Proxy struct {
	upstreams map[string]*upstream.Upstream
	names     []string
	hub       *upstream.Hub
	log       io.Writer
}

// Options describes a proxy.
type Options struct {
	// Hub must be the hub the upstreams were built with, or their
	// notifications never reach the agent.
	Hub       *upstream.Hub
	Upstreams []*upstream.Upstream
	// Log gets the diagnostics. It is stderr in the real program.
	Log io.Writer
}

// New returns a proxy over the given upstreams.
func New(options Options) *Proxy {
	proxy := &Proxy{
		upstreams: map[string]*upstream.Upstream{},
		hub:       options.Hub,
		log:       options.Log,
	}
	for _, u := range options.Upstreams {
		proxy.upstreams[u.Name()] = u
		proxy.names = append(proxy.names, u.Name())
	}
	sort.Strings(proxy.names)
	return proxy
}

// FromConfigOptions describes where FromConfig gets its parts.
type FromConfigOptions struct {
	Config *config.Config
	Store  store.Store
	Log    io.Writer
}

// FromConfig builds the upstreams described by the config. Nothing is started
// yet.
func FromConfig(options FromConfigOptions) *Proxy {
	hub := &upstream.Hub{}
	var upstreams []*upstream.Upstream
	for _, name := range options.Config.Names() {
		connector, err := connectorFor(name, options)
		if err != nil {
			upstream.Log(options.Log, fmt.Sprintf("skipping %q: %v", name, err))
			continue
		}
		upstreams = append(upstreams, upstream.New(upstream.Config{
			Name:      name,
			Connector: connector,
			Hub:       hub,
			Log:       options.Log,
		}))
	}
	return New(Options{Hub: hub, Upstreams: upstreams, Log: options.Log})
}

func connectorFor(name string, options FromConfigOptions) (upstream.Connector, error) {
	transport, err := options.Config.Servers[name].Transport()
	if err != nil {
		return nil, err
	}
	if transport.HTTP != nil {
		return httpConnector(transport.HTTP, options)
	}
	return &upstream.StdioConnector{
		Name: name,
		Spec: upstream.StdioSpec{
			Command: transport.Stdio.Command,
			Args:    transport.Stdio.Args,
			Env:     transport.Stdio.Env,
		},
		Store: options.Store,
		Log:   options.Log,
	}, nil
}

func httpConnector(transport *config.HTTPTransport, options FromConfigOptions) (upstream.Connector, error) {
	if transport.OAuth != nil {
		return nil, fmt.Errorf("OAuth upstreams are not supported yet")
	}
	return &upstream.HTTPConnector{
		Spec:  upstream.HTTPSpec{URL: transport.URL, Headers: transport.Headers},
		Store: options.Store,
	}, nil
}

// Upstreams returns the upstreams in name order, for `toolward check`.
func (p *Proxy) Upstreams() []*upstream.Upstream {
	upstreams := make([]*upstream.Upstream, 0, len(p.names))
	for _, name := range p.names {
		upstreams = append(upstreams, p.upstreams[name])
	}
	return upstreams
}

// Shutdown closes every upstream, all at once.
func (p *Proxy) Shutdown() {
	var group sync.WaitGroup
	for _, u := range p.upstreams {
		group.Add(1)
		go func() {
			defer group.Done()
			u.Shutdown()
		}()
	}
	group.Wait()
}

// Server returns the handler for one connection of an agent.
func (p *Proxy) Server() *mcpwire.Server {
	return mcpwire.NewServer(mcpwire.ServerConfig{
		Info:          mcpwire.Implementation{Name: "toolward", Version: version.Version()},
		Capabilities:  json.RawMessage(capabilities),
		Methods:       p,
		OnInitialized: p.hub.SetDownstream,
	})
}

// Serve answers the agent on the transport until the connection ends.
func (p *Proxy) Serve(transport mcpwire.Transport) *mcpwire.Peer {
	return mcpwire.NewPeer(transport, p.Server())
}

// HandleRequest answers one request of the agent.
func (p *Proxy) HandleRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "tools/list":
		return p.listTools(ctx)
	case "tools/call":
		return p.callTool(ctx, params)
	case "resources/list":
		return p.listResources(ctx)
	case "resources/templates/list":
		return p.listResourceTemplates()
	case "resources/read":
		return p.readResource(ctx, params)
	case "prompts/list":
		return p.listPrompts(ctx)
	case "prompts/get":
		return p.getPrompt(ctx, params)
	}
	return nil, mcpwire.MethodNotFound(method)
}
