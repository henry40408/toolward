package main

import (
	"fmt"
	"io"

	"github.com/henry40408/toolward/internal/oauth"
)

func runAuthLogin(p process, inv *invocation) error {
	server := inv.argument(0)
	cfg, err := loadConfig(inv)
	if err != nil {
		return err
	}
	url, oauthConfig, err := cfg.OAuthServer(server)
	if err != nil {
		return err
	}
	credentials, err := p.newStore()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	err = oauth.Login(ctx, oauth.LoginRequest{
		Server:   server,
		URL:      url,
		OAuth:    oauthConfig,
		Store:    credentials,
		Announce: announceLogin(p.stderr),
		Open:     oauth.OpenBrowser,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(p.stdout, "logged in to %q\n", server)
	return err
}

func announceLogin(stderr io.Writer) func(string) {
	return func(authURL string) {
		_, _ = fmt.Fprintf(stderr, "Opening your browser. If it does not open, visit:\n%s\n", authURL)
	}
}

func runAuthLogout(p process, inv *invocation) error {
	server := inv.argument(0)
	credentials, err := p.newStore()
	if err != nil {
		return err
	}
	existed, err := oauth.Logout(credentials, server)
	if err != nil {
		return err
	}
	if existed {
		_, err = fmt.Fprintf(p.stdout, "logged out of %q\n", server)
	} else {
		_, err = fmt.Fprintf(p.stdout, "no login stored for %q\n", server)
	}
	return err
}
