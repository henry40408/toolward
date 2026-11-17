package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/henry40408/toolward/internal/importer"
)

func runImport(p process, inv *invocation) error {
	file := inv.argument(0)
	source, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("cannot read %s: %v", file, unwrapPathError(err))
	}
	plan, err := importer.NewPlan(string(source))
	if err != nil {
		return err
	}
	if inv.apply {
		if err := applyPlan(p, inv, plan); err != nil {
			return err
		}
	}
	return importer.Report(plan, inv.apply, p.stdout)
}

func applyPlan(p process, inv *invocation, plan *importer.Plan) error {
	credentials, err := p.newStore()
	if err != nil {
		return err
	}
	path, err := configPathOf(inv)
	if err != nil {
		return err
	}
	return importer.Apply(plan, credentials, path)
}

func unwrapPathError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}
