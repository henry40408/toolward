package importer

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/interpolate"
	"github.com/henry40408/toolward/internal/store"
)

// Apply stores the secrets and writes the servers into the config file at
// path, merging with what is there (comments in an existing file are lost).
// Nothing is written unless every check passes first. If storing a secret or
// replacing the file fails, the accounts this run created are deleted again.
//
// An account that holds a different secret is not overwritten: the secret goes
// to the next free name (`<name>-2`, ...), and the plan is updated to say so,
// so Report shows the names that were really used.
//
// Limitation: the check (Get) and the write (Set) are not atomic, so a
// concurrent writer to the same account can still be overwritten, or have its
// new account deleted again by the rollback.
func Apply(plan *Plan, credentials store.Store, path string) error {
	for _, secret := range plan.secrets {
		if err := store.ValidateUserAccount(secret.account); err != nil {
			return err
		}
	}
	document, err := readExistingDocument(path)
	if err != nil {
		return err
	}
	existing, err := existingServers(document)
	if err != nil {
		return err
	}
	for name := range plan.servers {
		if _, taken := existing[name]; taken {
			return fmt.Errorf("the config already has a server named %q", name)
		}
	}
	chosen, err := chooseAccounts(plan, credentials, referencedAccounts(existing))
	if err != nil {
		return err
	}

	servers, moves := retargetAll(plan, chosen)
	for name, server := range servers {
		existing[name] = server
	}
	text := encodePretty(document)
	// The merged file must load, or nothing is stored.
	if _, err := config.Parse(text); err != nil {
		return fmt.Errorf("the merged config is not valid: %s", safeError(err))
	}

	err = storeAndReplace(replacement{store: credentials, path: path, text: text, chosen: chosen, secrets: plan.secrets})
	if err != nil {
		return err
	}
	for i, pick := range chosen {
		plan.secrets[i].account = pick.account
	}
	plan.servers = servers
	plan.Moves = moves
	return nil
}

// existingServers returns the `mcpServers` object of document, adding an
// empty one when there is none.
func existingServers(document object) (object, error) {
	value, present := document["mcpServers"]
	if !present {
		servers := object{}
		document["mcpServers"] = servers
		return servers, nil
	}
	servers, ok := value.(object)
	if !ok {
		return nil, errors.New(`"mcpServers" in the existing config is not an object`)
	}
	return servers, nil
}

// readExistingDocument reads the config at path as a JSON object. A missing
// file or `null` is empty.
func readExistingDocument(path string) (object, error) {
	text, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return object{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, unwrapPathError(err))
	}
	value, err := parseDocument(string(text))
	if err != nil {
		return nil, errors.New("the existing config is not valid JSON")
	}
	if value == nil {
		return object{}, nil
	}
	document, ok := value.(object)
	if !ok {
		return nil, errors.New("the existing config is not a JSON object")
	}
	return document, nil
}

func unwrapPathError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// referencedAccounts lists every account named by a `${keychain:...}`
// reference inside the servers.
func referencedAccounts(servers object) map[string]bool {
	accounts := map[string]bool{}
	collectReferences(servers, accounts)
	return accounts
}

func collectReferences(value any, accounts map[string]bool) {
	switch typed := value.(type) {
	case string:
		// Text that does not parse names no account.
		found, _ := interpolate.References(typed)
		for _, account := range found {
			accounts[account] = true
		}
	case []any:
		for _, item := range typed {
			collectReferences(item, accounts)
		}
	case object:
		for _, item := range typed {
			collectReferences(item, accounts)
		}
	}
}

// chosenAccount is the account that holds one secret, and whether this run has
// to create it.
type chosenAccount struct {
	account string
	create  bool
}

// maxAccountSuffix bounds the search for a free account name.
const maxAccountSuffix = 10_000

// chooseAccounts picks the account that will hold each secret: the planned
// name, or the next free `<name>-2`, `-3`, ... when that account is taken. An
// account is taken when it holds a different secret or the existing config
// refers to it. An account that already holds the same secret is reused.
func chooseAccounts(plan *Plan, credentials store.Store, referenced map[string]bool) ([]chosenAccount, error) {
	planned := map[string]bool{}
	for _, secret := range plan.secrets {
		planned[secret.account] = true
	}
	claimed := map[string]bool{}
	var chosen []chosenAccount
	for _, secret := range plan.secrets {
		pick, err := chooseAccount(secret, accountLimits{planned: planned, claimed: claimed, referenced: referenced}, credentials)
		if err != nil {
			return nil, err
		}
		claimed[pick.account] = true
		chosen = append(chosen, pick)
	}
	return chosen, nil
}

// accountLimits are the names a candidate account must avoid.
type accountLimits struct {
	planned, claimed, referenced map[string]bool
}

func chooseAccount(secret plannedSecret, limits accountLimits, credentials store.Store) (chosenAccount, error) {
	for n := 1; n <= maxAccountSuffix; n++ {
		candidate := secret.account
		if n > 1 {
			candidate = fmt.Sprintf("%s-%d", secret.account, n)
		}
		if limits.claimed[candidate] || limits.referenced[candidate] || (n > 1 && limits.planned[candidate]) {
			continue
		}
		if err := store.ValidateUserAccount(candidate); err != nil {
			return chosenAccount{}, err
		}
		current, found, err := credentials.Get(candidate)
		if err != nil {
			return chosenAccount{}, err
		}
		if !found {
			return chosenAccount{account: candidate, create: true}, nil
		}
		if current == secret.value {
			return chosenAccount{account: candidate}, nil
		}
	}
	return chosenAccount{}, fmt.Errorf("no free account name found for %q", secret.account)
}

// retargetAll returns copies of the planned servers and moves that use the
// chosen accounts.
func retargetAll(plan *Plan, chosen []chosenAccount) (object, []Move) {
	servers := cloneObject(plan.servers)
	moves := append([]Move(nil), plan.Moves...)
	for i := range moves {
		if moves[i].Account == chosen[i].account {
			continue
		}
		retarget(servers, moves[i], chosen[i].account)
		moves[i].Account = chosen[i].account
	}
	return servers, moves
}

// retarget points the value that moved describes at account instead of
// moved.Account.
func retarget(servers object, moved Move, account string) {
	kind, key, found := strings.Cut(moved.Place, " ")
	if !found {
		return
	}
	if kind == "header" {
		kind = "headers"
	}
	server, _ := servers[moved.Server].(object)
	table, _ := server[kind].(object)
	text, ok := table[key].(string)
	if !ok {
		return
	}
	table[key] = strings.ReplaceAll(text, "${keychain:"+moved.Account+"}", "${keychain:"+account+"}")
}
