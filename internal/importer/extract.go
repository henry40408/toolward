package importer

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/henry40408/toolward/internal/store"
)

// plannedSecret is a secret value that goes into the credential store.
type plannedSecret struct {
	account string
	value   string
}

// planner collects what the servers of one file need.
type planner struct {
	moves   []Move
	secrets []plannedSecret
	notes   []string
	used    map[string]bool
}

// mark is the length of each list, to undo what a server added.
type mark struct {
	moves, secrets, notes int
}

func (p *planner) mark() mark {
	return mark{moves: len(p.moves), secrets: len(p.secrets), notes: len(p.notes)}
}

func (p *planner) rollBackTo(m mark) {
	p.moves = p.moves[:m.moves]
	p.secrets = p.secrets[:m.secrets]
	p.notes = p.notes[:m.notes]
}

// unique returns wanted, or the first of wanted-2, wanted-3, ... not used yet.
func (p *planner) unique(wanted string) string {
	account := wanted
	for n := 2; p.used[account]; n++ {
		account = fmt.Sprintf("%s-%d", wanted, n)
	}
	p.used[account] = true
	return account
}

// extractSecrets replaces the secret-looking string values of table. Keys go
// in sorted order, so the plan does not depend on the file's order.
func (p *planner) extractSecrets(server, kind string, table object) {
	for _, key := range slices.Sorted(maps.Keys(table)) {
		text, ok := table[key].(string)
		if !ok || text == "" || (!looksSecret(key) && !hasSecretPrefix(text)) {
			continue
		}
		if strings.Contains(text, "${") {
			p.notes = append(p.notes, fmt.Sprintf(
				"%s: %s %s contains a ${...} reference and was left as is; toolward only understands ${keychain:...}",
				server, kind, key))
			continue
		}
		table[key] = p.moveToStore(server, kind, key, text)
	}
}

// moveToStore records the move of one value and returns what replaces it.
func (p *planner) moveToStore(server, kind, key, text string) string {
	scheme, secret := splitScheme(text)
	account := p.unique(accountName(server, key))
	p.secrets = append(p.secrets, plannedSecret{account: account, value: secret})
	p.moves = append(p.moves, Move{Server: server, Place: kind + " " + key, Account: account})
	return scheme + "${keychain:" + account + "}"
}

// accountName turns free text into an account name.
func accountName(server, key string) string {
	var name strings.Builder
	for _, char := range asciiLower(server + "-" + key) {
		if isASCIIAlphanumeric(char) || char == '.' || char == '_' || char == '-' {
			name.WriteRune(char)
			continue
		}
		name.WriteRune('-')
	}
	for _, prefix := range store.ReservedPrefixes {
		if strings.HasPrefix(name.String(), prefix) {
			return "imported-" + name.String()
		}
	}
	return name.String()
}

// splitScheme splits `Bearer abc` into `Bearer ` and `abc`. Other values have
// no scheme.
func splitScheme(value string) (scheme, secret string) {
	for _, candidate := range []string{"Bearer ", "Basic ", "Token "} {
		if len(value) > len(candidate) && asciiLower(value[:len(candidate)]) == asciiLower(candidate) {
			return value[:len(candidate)], value[len(candidate):]
		}
	}
	return "", value
}
