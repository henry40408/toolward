package main

import (
	"github.com/henry40408/toolward/internal/check"
	"github.com/henry40408/toolward/internal/proxy"
	"github.com/henry40408/toolward/internal/store"
)

func runCheck(p process, inv *invocation) error {
	cfg, err := loadConfig(inv)
	if err != nil {
		return err
	}
	keychain, err := p.newStore()
	if err != nil {
		return err
	}
	credentials := store.NewCached(keychain, p.stderr)
	reports := check.CheckSecrets(cfg, credentials)
	if inv.tools {
		ctx, stop := signalContext()
		defer stop()
		running := proxy.FromConfig(proxy.FromConfigOptions{Config: cfg, Store: credentials, Log: p.stderr})
		reports = check.CheckTools(ctx, running, reports)
	}
	if err := render(p, inv, reports); err != nil {
		return err
	}
	if !check.AllOK(reports) {
		return errCheckFailed
	}
	return nil
}

func render(p process, inv *invocation, reports []*check.ServerReport) error {
	if inv.format == "json" {
		return check.RenderJSON(p.stdout, reports)
	}
	noColor, _ := p.lookupEnv("NO_COLOR")
	return check.RenderText(p.stdout, reports, check.TextOptions{
		ToolsChecked: inv.tools,
		Color:        check.WantsColor(p.stdoutIsTerminal, noColor),
	})
}
