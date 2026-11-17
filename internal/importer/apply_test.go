package importer

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/interpolate"
	"github.com/henry40408/toolward/internal/store"
)

const originalConfig = `{"mcpServers": {"keep": {"command": "x"}}}`

// failingStore fails the Nth Set (1-based) and, optionally, every Delete.
type failingStore struct {
	*store.Memory
	failSetAt  int
	failDelete bool
	sets       int
}

func (s *failingStore) Set(account, secret string) error {
	s.sets++
	if s.sets == s.failSetAt {
		return &store.BackendError{Message: "denied"}
	}
	return s.Memory.Set(account, secret)
}

func (s *failingStore) Delete(account string) (bool, error) {
	if s.failDelete {
		return false, &store.BackendError{Message: "denied"}
	}
	return s.Memory.Delete(account)
}

// dirOnSet creates a directory at the config path on every Set, so the final
// rename fails after the secrets are stored.
type dirOnSet struct {
	*store.Memory
	dir string
}

func (s *dirOnSet) Set(account, secret string) error {
	_ = os.Mkdir(s.dir, 0o755)
	return s.Memory.Set(account, secret)
}

func configPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "config.json")
}

func writeConfig(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readConfig(t *testing.T, path string) string {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func assertSecret(t *testing.T, credentials store.Store, account, want string) {
	t.Helper()
	got, found, err := credentials.Get(account)
	if err != nil {
		t.Fatal(err)
	}
	if want == "" && found {
		t.Errorf("%s exists", account)
	}
	if want != "" && got != want {
		t.Errorf("%s = %q, want %q", account, got, want)
	}
}

func assertNoTemp(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(strings.TrimSuffix(path, ".json") + ".json.tmp"); err == nil {
		t.Error("temp file left behind")
	}
}

func TestApplyStoresSecretsAndMergesConfig(t *testing.T) {
	path := configPath(t)
	writeConfig(t, path, originalConfig)
	credentials := store.NewMemory()

	if err := Apply(mustPlan(t, testSource), credentials, path); err != nil {
		t.Fatal(err)
	}

	assertSecret(t, credentials, "gh-authorization", "ghp_SECRET1")
	assertSecret(t, credentials, "db-db_token", "tok-SECRET2")
	text := readConfig(t, path)
	if strings.Contains(text, "SECRET") {
		t.Errorf("config holds a secret: %s", text)
	}
	parsed, err := config.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Names(); !slices.Equal(got, []string{"db", "gh", "keep"}) {
		t.Errorf("names = %v", got)
	}
}

func TestApplyRefusesConflictsBeforeChangingAnything(t *testing.T) {
	path := configPath(t)
	writeConfig(t, path, `{"mcpServers": {"gh": {"command": "x"}}}`)
	credentials := store.NewMemory()

	err := Apply(mustPlan(t, testSource), credentials, path)

	if err == nil || !strings.Contains(err.Error(), "already has a server") {
		t.Errorf("err = %v", err)
	}
	assertSecret(t, credentials, "db-db_token", "")
}

func TestFailedSetRollsBackOnlyNewAccounts(t *testing.T) {
	path := configPath(t)
	writeConfig(t, path, originalConfig)
	// db-db_token already holds the same value, so it is not ours to delete.
	credentials := &failingStore{Memory: store.NewMemoryWith(map[string]string{"db-db_token": "tok-SECRET2"}), failSetAt: 1}

	// Order is db (existing, reused), gh (the failing set).
	err := Apply(mustPlan(t, testSource), credentials, path)

	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("err = %v", err)
	}
	if got := readConfig(t, path); got != originalConfig {
		t.Errorf("config changed: %s", got)
	}
	assertNoTemp(t, path)
	assertSecret(t, credentials, "db-db_token", "tok-SECRET2")
	assertSecret(t, credentials, "gh-authorization", "")
}

func TestFailureAfterASetDeletesWhatThisRunCreated(t *testing.T) {
	path := configPath(t)
	writeConfig(t, path, originalConfig)
	credentials := &failingStore{Memory: store.NewMemoryWith(map[string]string{"other": "o-SECRET9"}), failSetAt: 2}

	err := Apply(mustPlan(t, testSource), credentials, path)

	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("err = %v", err)
	}
	assertSecret(t, credentials, "db-db_token", "")
	assertSecret(t, credentials, "gh-authorization", "")
	assertSecret(t, credentials, "other", "o-SECRET9")
	if got := readConfig(t, path); got != originalConfig {
		t.Errorf("config changed: %s", got)
	}
	assertNoTemp(t, path)
}

func TestRollbackFailureIsReportedByAccountNameOnly(t *testing.T) {
	path := configPath(t)
	credentials := &failingStore{Memory: store.NewMemory(), failSetAt: 2, failDelete: true}

	err := Apply(mustPlan(t, testSource), credentials, path)

	if err == nil {
		t.Fatal("Apply succeeded")
	}
	text := err.Error()
	if !strings.Contains(text, "denied") || !strings.Contains(text, "db-db_token") || strings.Contains(text, "SECRET") {
		t.Errorf("err = %s", text)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("config was written")
	}
	assertNoTemp(t, path)
}

func TestFailedRenameDeletesWhatThisRunCreated(t *testing.T) {
	path := configPath(t)
	credentials := &dirOnSet{
		Memory: store.NewMemoryWith(map[string]string{"other": "o-SECRET9", "db-db_token": "tok-SECRET2"}),
		dir:    path,
	}

	err := Apply(mustPlan(t, testSource), credentials, path)

	if err == nil || !strings.Contains(err.Error(), "cannot replace") {
		t.Errorf("err = %v", err)
	}
	// gh-authorization was created by this run; the other two were not.
	assertSecret(t, credentials, "gh-authorization", "")
	assertSecret(t, credentials, "other", "o-SECRET9")
	assertSecret(t, credentials, "db-db_token", "tok-SECRET2")
	assertNoTemp(t, path)
}

func TestABearerHeaderIsRetargetedKeepingItsScheme(t *testing.T) {
	path := configPath(t)
	credentials := store.NewMemoryWith(map[string]string{"gh-authorization": "different-SECRET"})
	plan := mustPlan(t, testSource)

	if err := Apply(plan, credentials, path); err != nil {
		t.Fatal(err)
	}

	text := readConfig(t, path)
	if !strings.Contains(text, "Bearer ${keychain:gh-authorization-2}") || strings.Contains(text, "${keychain:gh-authorization}") {
		t.Errorf("config = %s", text)
	}
	if !strings.Contains(plan.ConfigJSON(), "Bearer ${keychain:gh-authorization-2}") {
		t.Errorf("plan = %s", plan.ConfigJSON())
	}
	assertSecret(t, credentials, "gh-authorization", "different-SECRET")
}

func TestASuffixThatAnotherEntryWantsIsSkipped(t *testing.T) {
	path := configPath(t)
	// Both keys map to s-a_token; the planner names them s-a_token and s-a_token-2.
	source := `{"mcpServers": {"s": {"command": "y",
		"env": {"A_TOKEN": "tok-SECRET4", "a_token": "tok-SECRET5"}}}}`
	credentials := store.NewMemoryWith(map[string]string{"s-a_token": "different-SECRET"})
	plan := mustPlan(t, source)
	if got := accountsOf(plan); !slices.Equal(got, []string{"s-a_token", "s-a_token-2"}) {
		t.Fatalf("planned = %v", got)
	}

	if err := Apply(plan, credentials, path); err != nil {
		t.Fatal(err)
	}

	if got := accountsOf(plan); !slices.Equal(got, []string{"s-a_token-3", "s-a_token-2"}) {
		t.Errorf("accounts = %v", got)
	}
	assertSecret(t, credentials, "s-a_token-3", "tok-SECRET4")
	assertSecret(t, credentials, "s-a_token-2", "tok-SECRET5")
}

func TestASuffixedAccountWithTheSameValueIsReusedAndKeptOnRollback(t *testing.T) {
	path := configPath(t)
	held := map[string]string{"gh-authorization": "different-SECRET", "gh-authorization-2": "ghp_SECRET1"}
	// Only db-db_token needs a Set; make it fail.
	failing := &failingStore{Memory: store.NewMemoryWith(held), failSetAt: 1}

	err := Apply(mustPlan(t, testSource), failing, path)

	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("err = %v", err)
	}
	if failing.sets != 1 {
		t.Errorf("sets = %d", failing.sets)
	}
	assertSecret(t, failing, "gh-authorization-2", "ghp_SECRET1")
	assertSecret(t, failing, "gh-authorization", "different-SECRET")

	// On success the reused account is referenced and no extra account exists.
	credentials := store.NewMemoryWith(held)
	if err := Apply(mustPlan(t, testSource), credentials, path); err != nil {
		t.Fatal(err)
	}
	if text := readConfig(t, path); !strings.Contains(text, "${keychain:gh-authorization-2}") {
		t.Errorf("config = %s", text)
	}
	assertSecret(t, credentials, "gh-authorization-3", "")
}

func TestPlanIsUnchangedAfterAFailedApply(t *testing.T) {
	path := configPath(t)
	credentials := &failingStore{
		Memory:    store.NewMemoryWith(map[string]string{"gh-authorization": "different-SECRET"}),
		failSetAt: 2,
	}
	plan := mustPlan(t, testSource)
	configBefore := plan.ConfigJSON()
	movesBefore := slices.Clone(plan.Moves)
	secretsBefore := slices.Clone(plan.secrets)

	if err := Apply(plan, credentials, path); err == nil {
		t.Fatal("Apply succeeded")
	}

	if plan.ConfigJSON() != configBefore || !slices.Equal(plan.Moves, movesBefore) || !slices.Equal(plan.secrets, secretsBefore) {
		t.Error("plan changed")
	}
}

func TestATakenAccountGetsASuffixedName(t *testing.T) {
	path := configPath(t)
	// The existing config refers to db-db_token-2, so it is not free either.
	writeConfig(t, path, `{"mcpServers": {"keep": {"command": "x", "env": {"A": "${keychain:db-db_token-2}"}}}}`)
	credentials := store.NewMemoryWith(map[string]string{"db-db_token": "different-SECRET"})
	plan := mustPlan(t, testSource)

	if err := Apply(plan, credentials, path); err != nil {
		t.Fatal(err)
	}

	assertSecret(t, credentials, "db-db_token", "different-SECRET")
	assertSecret(t, credentials, "db-db_token-3", "tok-SECRET2")
	assertSecret(t, credentials, "db-db_token-2", "")
	if got := accountsOf(plan); !slices.Equal(got, []string{"db-db_token-3", "gh-authorization"}) {
		t.Errorf("accounts = %v", got)
	}
	if out := reportOf(t, plan, true); !strings.Contains(out, "${keychain:db-db_token-3}") {
		t.Errorf("report = %s", out)
	}
	assertExpandsToOriginals(t, path, credentials)
}

// assertExpandsToOriginals checks that the written config and the store give
// back the values of the source file.
func assertExpandsToOriginals(t *testing.T, path string, credentials store.Store) {
	t.Helper()
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := interpolate.Expand(loaded.Servers["db"].Env["DB_TOKEN"], credentials)
	if err != nil || token != "tok-SECRET2" {
		t.Errorf("token = %q, %v", token, err)
	}
	auth, err := interpolate.Expand(loaded.Servers["gh"].Headers["Authorization"], credentials)
	if err != nil || auth != "Bearer ghp_SECRET1" {
		t.Errorf("auth = %q, %v", auth, err)
	}
}

func TestApplyChecksTheMergedConfigAndLeavesNoTemp(t *testing.T) {
	path := configPath(t)
	writeConfig(t, path, `{"mcpServers": {"a-b": {"command": "x"}}}`)
	credentials := store.NewMemory()
	source := `{"mcpServers": {"a_b": {"command": "y", "env": {"T_TOKEN": "tok-SECRET3"}}}}`

	err := Apply(mustPlan(t, source), credentials, path)

	if err == nil || !strings.Contains(err.Error(), "merged") {
		t.Errorf("err = %v", err)
	}
	assertSecret(t, credentials, "a_b-t_token", "")
	assertNoTemp(t, path)
}

func TestWrittenConfigIsPrivate(t *testing.T) {
	path := configPath(t)

	if err := Apply(mustPlan(t, testSource), store.NewMemory(), path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o", mode)
	}
}

func TestApplyWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "config.json")
	writeConfig(t, target, originalConfig)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := Apply(mustPlan(t, testSource), store.NewMemory(), link); err != nil {
		t.Fatal(err)
	}

	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link was replaced: %v %v", info, err)
	}
	if !strings.Contains(readConfig(t, target), `"db"`) {
		t.Error("target was not updated")
	}
}

func TestApplyRejectsAnExistingConfigThatIsNotAnObject(t *testing.T) {
	for _, existing := range []string{"[]", `{"mcpServers": []}`, "{"} {
		path := configPath(t)
		writeConfig(t, path, existing)

		if err := Apply(mustPlan(t, testSource), store.NewMemory(), path); err == nil {
			t.Errorf("Apply accepted %q", existing)
		}
		if got := readConfig(t, path); got != existing {
			t.Errorf("config changed: %s", got)
		}
	}
}

func TestApplyTreatsAnEmptyExistingConfigAsEmpty(t *testing.T) {
	path := configPath(t)
	writeConfig(t, path, "// nothing yet\n")

	if err := Apply(mustPlan(t, testSource), store.NewMemory(), path); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefusesAReservedAccount(t *testing.T) {
	plan := mustPlan(t, testSource)
	plan.secrets[0].account = "oauth.x"

	err := Apply(plan, store.NewMemory(), configPath(t))

	var reserved *store.ReservedAccountError
	if !errors.As(err, &reserved) {
		t.Errorf("err = %v", err)
	}
}
