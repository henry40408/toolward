package config

import (
	"encoding/json"
	"fmt"
)

// decodeObject decodes the members of a JSON object whose names are keys of
// known into the pointers they map to, and returns the other members. Names
// match exactly, unlike encoding/json struct tags, which ignore case.
func decodeObject(data []byte, known map[string]any) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, err
	}
	extra := map[string]json.RawMessage{}
	for name, raw := range members {
		target, ok := known[name]
		if !ok {
			extra[name] = raw
			continue
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return nil, fmt.Errorf("field %q: %w", name, err)
		}
	}
	return extra, nil
}

func decode(data []byte) (*Config, error) {
	config := &Config{Servers: map[string]*ServerConfig{}}
	_, err := decodeObject(data, map[string]any{"mcpServers": &config.Servers})
	if err != nil {
		return nil, err
	}
	if config.Servers == nil {
		config.Servers = map[string]*ServerConfig{}
	}
	for name, server := range config.Servers {
		if server == nil {
			return nil, fmt.Errorf("server %q: expected an object, found null", name)
		}
	}
	return config, nil
}

// UnmarshalJSON decodes a server entry, keeping unknown fields in Extra.
func (s *ServerConfig) UnmarshalJSON(data []byte) error {
	extra, err := decodeObject(data, map[string]any{
		"type":    &s.Kind,
		"command": &s.Command,
		"args":    &s.Args,
		"env":     &s.Env,
		"url":     &s.URL,
		"headers": &s.Headers,
		"oauth":   &s.OAuth,
	})
	s.Extra = extra
	return err
}

// UnmarshalJSON decodes the "oauth" setting.
func (o *OAuthConfig) UnmarshalJSON(data []byte) error {
	_, err := decodeObject(data, map[string]any{
		"scopes":       &o.Scopes,
		"clientId":     &o.ClientID,
		"clientSecret": &o.ClientSecret,
		"callbackPort": &o.CallbackPort,
	})
	return err
}
