# Architecture

toolward is one stdio MCP server for the agent (`toolward serve`). Behind it, it connects to the real MCP servers listed in its config. Credentials stay in the OS credential store and are only read when a connection starts.

```
agent ──stdio──> proxy ──> upstream ──> connect (stdio | http | oauth) ──> real MCP server
                   │          │
                   │          └─ redact: known secrets -> [REDACTED]
                   └─ names: <server>__<tool>
                              ▲
                  store (Keychain) <── interpolate ${keychain:<account>}
```

## Packages

| Package | Role |
| --- | --- |
| `cmd/toolward` | Command line (`serve`, `check`, `secret`, `auth`, `import`), built on `flag` with one flag set per subcommand. `serve` keeps stdout free, because it carries the MCP protocol. |
| `internal/config` | Parses the JSONC `mcpServers` config (via `hujson`) and validates it. Decides the transport of each server and rejects `${keychain:...}` in `command`, `args` and `url`. |
| `internal/interpolate` | Expands `${keychain:<account>}` and `$${`. Any other `${...}` is an error, so a typo never reaches an upstream. |
| `internal/store` | `Store` interface with a Keychain backend (`keychain_darwin.go`, build tag `darwin`), a read cache and an in-memory backend for tests. Config files hold account names only. Other platforms get an error that no credential store is available. |
| `internal/proxy` | The MCP server the agent talks to. Merges tools, resources and prompts of all upstreams and forwards requests. |
| `internal/upstream` | One upstream: lazy connect, reconnect with back-off, timeouts, and redaction of results. Holds the stdio and HTTP connectors. |
| `internal/mcpwire` | The MCP wire layer: JSON-RPC 2.0 on `json.RawMessage`, a request/response peer, stdio and child-process transports, a streamable HTTP client (SSE, session loss, resumption), and the protocol lifecycle for both sides. |
| `internal/oauth` | OAuth 2.0 for HTTP upstreams: RFC 9728 and RFC 8414 discovery, RFC 7591 registration, PKCE login with a loopback redirect, token storage in the credential store, refresh at `serve` time. |
| `internal/redact` | Finds known secrets in text and JSON values, in every encoding listed in the README, and replaces them with `[REDACTED]`. |
| `internal/cache` | Caching hints (`ttlMs`, `cacheScope`) of list results. Merges the hints of many upstreams into the weakest one. |
| `internal/names` | Builds the tool names the agent sees and keeps them inside the client name limit. |
| `internal/check` | The `check` report, as text or JSON. |
| `internal/importer` | Plans and applies the move of plaintext secrets from an existing `mcp.json` into the credential store. |
| `internal/rawjson` | Reads and edits single fields of raw JSON objects, so unknown fields and key order survive. |
| `internal/version` | The build version. |
| `internal/testing/fakeupstream`, `internal/testing/httpfake` | Test doubles: a stdio MCP server and an HTTP MCP and OAuth server. |

### Why there is no MCP SDK

Production code does not use an MCP SDK. A proxy must pass on fields it does not know, keep the key order of results it did not change, and turn off the response cache of its upstream connections. The Go SDK models typed structs, caches list results under the newest protocol version, and keeps the hooks of its Streamable HTTP session private, so each of these needs a workaround. `internal/mcpwire` keeps results as `json.RawMessage` and decodes only the fields the proxy needs. The Go SDK is a test-only dependency: the fake upstream is built with it, which shows that `mcpwire` works with the reference implementation.

## Request flow

1. `serve` loads the config and builds one upstream per server. Nothing is started yet.
2. On the first request that needs an upstream, its connector expands `${keychain:...}`, reads the secrets, starts the child process or opens the HTTP session, and remembers the secret values for redaction.
3. `tools/list` asks every upstream and renames each tool to `<server>__<tool>` (`internal/names`). An upstream that fails or is too slow is left out of the list and retried later.
4. `tools/call` maps the name back to the original tool, forwards the call, and passes the result through `internal/redact`. If a result cannot be inspected, the call fails.
5. Upstream notifications and requests that go back to the agent use the downstream peer that the proxy holds.

## Design decisions

- **Secrets are resolved late.** A value is read from the store when a server starts, not when the config is loaded. `check` can therefore report missing secrets without reading any of them.
- **Redaction is best effort and fail closed.** It matches the secret as is, JSON-escaped, URL-encoded, base64 and per line. It cannot find a secret that an upstream hashes or splits. See the threat model in the README.
- **Only account names are logged.** Logs go to stderr; stdout is reserved for the protocol.
- **OAuth logins are separate from `serve`.** `serve` never opens a browser. Tokens live in the account `oauth.<server>`, a name that users cannot set with `secret set`.
- **The agent does the caching.** toolward turns off the response cache of its upstream connections and passes on the weakest `ttlMs` and `cacheScope` of the listings a result was merged from. A list with a missing upstream gets `ttlMs: 0`, because it is incomplete. A second cache here would add its age to the agent's.
- **The agent sees one server.** Failure of one upstream does not stop the others.
- **Config files are strict JSONC.** Comments and trailing commas are allowed. Unquoted keys, single quotes and hex numbers are not.

## Tests

- The `internal/proxy` integration tests drive the proxy against `internal/testing/fakeupstream`, a real child process: the test binary runs itself again with `TOOLWARD_FAKE_UPSTREAM=1`.
- The HTTP and OAuth paths run against `internal/testing/httpfake`, a local server.
- The `cmd/toolward` tests build the binary once in `TestMain` and run it.
- Unit tests sit next to the code. They use the in-memory store, so they never touch the Keychain. The real Keychain test runs only with `TOOLWARD_KEYCHAIN_TEST=1`.
