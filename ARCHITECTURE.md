# Architecture

toolward is one stdio MCP server for the agent (`toolward serve`). Behind it, it connects to the real MCP servers listed in its config. Credentials stay in the OS credential store and are only read when a connection starts.

```
agent ──stdio──> Proxy ──> Upstream ──> Connect (stdio | http | oauth) ──> real MCP server
                   │          │
                   │          └─ redact: known secrets -> [REDACTED]
                   └─ names: <server>__<tool>
                              ▲
                  CredentialStore (Keychain) <── interpolate ${keychain:<account>}
```

## Modules

| Module | Role |
| --- | --- |
| `main.rs`, `cli.rs` | Command line (`serve`, `check`, `secret`, `auth`, `import`). `serve` keeps stdout free, because it carries the MCP protocol. |
| `config.rs` | Parses the JSONC `mcpServers` config and validates it. Decides the transport of each server and rejects `${keychain:...}` in `command`, `args` and `url`. |
| `interpolate.rs` | Expands `${keychain:<account>}` and `$${`. Any other `${...}` is an error, so a typo never reaches an upstream. |
| `store.rs` | `CredentialStore` trait with a Keychain backend (`KeyringStore`), a read cache (`CachedStore`) and an in-memory backend for tests. Config files hold account names only. |
| `proxy.rs` | The MCP server the agent talks to. Merges tools, resources and prompts of all upstreams and forwards requests. |
| `upstream.rs` | One upstream: lazy connect, reconnect with back-off, timeouts, and redaction of results. Holds the stdio and HTTP connectors. |
| `oauth.rs` | OAuth 2.0 for HTTP upstreams: PKCE login with a loopback redirect, token storage in the credential store, refresh at `serve` time. |
| `cache.rs` | Caching hints (`ttlMs`, `cacheScope`) of list results. Merges the hints of many upstreams into the weakest one. |
| `names.rs` | Builds the tool names the agent sees and keeps them inside the client name limit. |
| `import.rs` | Plans and applies the move of plaintext secrets from an existing `mcp.json` into the credential store. |

## Request flow

1. `serve` loads the config and builds one `Upstream` per server. Nothing is started yet.
2. On the first request that needs an upstream, its connector expands `${keychain:...}`, reads the secrets, starts the child process or opens the HTTP session, and remembers the secret values for redaction.
3. `tools/list` asks every upstream and renames each tool to `<server>__<tool>` (`names.rs`). An upstream that fails or is too slow is left out of the list and retried later.
4. `tools/call` maps the name back to the original tool, forwards the call, and passes the result through `redact_result`. If a result cannot be inspected, the call fails.
5. Upstream notifications and requests that go back to the agent use the `Hub`, which holds the downstream peer.

## Design decisions

- **Secrets are resolved late.** A value is read from the store when a server starts, not when the config is loaded. `check` can therefore report missing secrets without reading any of them.
- **Redaction is best effort and fail closed.** It matches the secret as is, JSON-escaped, URL-encoded, base64 and per line. It cannot find a secret that an upstream hashes or splits. See the threat model in the README.
- **Only account names are logged.** Logs go to stderr; stdout is reserved for the protocol.
- **OAuth logins are separate from `serve`.** `serve` never opens a browser. Tokens live in the account `oauth.<server>`, a name that users cannot set with `secret set`.
- **The agent does the caching.** toolward turns off the response cache of its upstream connections and passes on the weakest `ttlMs` and `cacheScope` of the listings a result was merged from. A list with a missing upstream gets `ttlMs: 0`, because it is incomplete. A second cache here would add its age to the agent's.
- **The agent sees one server.** Failure of one upstream does not stop the others.

## Tests

- `tests/proxy.rs` drives the proxy in-process against `examples/fake_upstream.rs`, a real child process, over an in-memory MCP connection.
- `tests/http.rs` covers the HTTP and OAuth paths.
- Unit tests sit next to the code. They use `MemoryStore`, so they never touch the Keychain.
