package importer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/henry40408/toolward/internal/store"
)

// replacement is one swap of the config file together with the secrets it
// needs.
type replacement struct {
	store   store.Store
	path    string
	text    string
	chosen  []chosenAccount
	secrets []plannedSecret
}

// storeAndReplace stores the secrets chosen as new, then replaces the file at
// r.path with r.text. If either step fails, the accounts this run created are
// deleted.
func storeAndReplace(r replacement) error {
	// Write through a symlink instead of replacing it.
	if resolved, err := filepath.EvalSymlinks(r.path); err == nil {
		r.path = resolved
	}
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return fmt.Errorf("cannot create %s: %v", dir, unwrapPathError(err))
	}
	temp := strings.TrimSuffix(r.path, filepath.Ext(r.path)) + ".json.tmp"
	var created []string
	err := writeAndSwap(r, temp, &created)
	if err == nil {
		return nil
	}
	_ = os.Remove(temp)
	left := rollBack(r.store, created)
	if len(left) == 0 {
		return err
	}
	return fmt.Errorf("%w; also could not remove the stored account(s): %s", err, strings.Join(left, ", "))
}

// writeAndSwap writes temp, stores the new secrets, then renames temp over the
// config. created lists the accounts it may have created, also on failure.
func writeAndSwap(r replacement, temp string, created *[]string) error {
	if err := writePrivate(temp, r.text); err != nil {
		return fmt.Errorf("cannot write %s: %v", temp, unwrapPathError(err))
	}
	for i, pick := range r.chosen {
		if !pick.create {
			continue
		}
		// A failed Set may still have created the account.
		*created = append(*created, pick.account)
		if err := r.store.Set(pick.account, r.secrets[i].value); err != nil {
			return fmt.Errorf("cannot store %s: %w", pick.account, err)
		}
	}
	if err := os.Rename(temp, r.path); err != nil {
		return fmt.Errorf("cannot replace %s: %v", r.path, unwrapPathError(err))
	}
	return nil
}

// rollBack deletes the accounts this run created and returns the ones that
// stayed.
func rollBack(credentials store.Store, created []string) []string {
	var left []string
	for _, account := range created {
		if _, err := credentials.Delete(account); err != nil {
			left = append(left, account)
		}
	}
	return left
}

// writePrivate creates path readable by the owner only.
func writePrivate(path, text string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(text); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
