# toolward

An MCP proxy that keeps credentials out of agent-readable files.

Coding agents read `mcp.json`, and a model that is too helpful will read a token from it into the conversation. toolward is a single stdio MCP server for the agent. It starts your real MCP servers behind it, and it keeps their credentials in the OS credential store (macOS Keychain), never in a file the agent can open.

```
Claude Code ──stdio──> toolward serve ──stdio──> local MCP server   (env from Keychain)
                                       └─HTTP──> remote MCP server  (headers or OAuth from Keychain)
```

- Tools appear as `<server>__<tool>`. Resources and prompts are proxied too.
- Secrets are filled in at start time and masked in everything the upstream sends back.
- macOS only for now (Keychain). Only stdio towards the agent.

## Install

```sh
cargo install --path . --locked
```

## Quick start

1. Store a secret. It is read from a hidden prompt, or from stdin. It never goes through the command line.

   ```sh
   toolward secret set github-token
   ```

2. Write `~/.config/toolward/config.json` (JSON with comments). `${keychain:<account>}` is replaced when the server starts:

   ```jsonc
   {
     "mcpServers": {
       "github": {
         "type": "http",
         "url": "https://api.githubcopilot.com/mcp/",
         "headers": { "Authorization": "Bearer ${keychain:github-token}" }
       },
       "db": {
         "command": "db-mcp",
         "args": ["--readonly"],
         "env": { "DB_PASSWORD": "${keychain:db-password}" }
       }
     }
   }
   ```

3. Check it, then point the agent at toolward only:

   ```sh
   toolward check            # config is valid, which secrets are missing
   toolward check --tools    # also connect and list the tool names
   ```

   ```json
   { "mcpServers": { "toolward": { "command": "toolward", "args": ["serve"] } } }
   ```

## Config

The format is the usual `mcpServers` map. Differences:

- `${keychain:<account>}` works in `env` values and `headers` values. An account is ASCII letters, digits, `.`, `_` and `-`. The Keychain service is always `toolward`. Use `$${` for a literal `${`.
- It is not allowed in `command`, `args` or `url`: those can show in process lists and logs. Put the secret in `env` or a header.
- A server name is at most 20 characters, ASCII letters, digits, `-` and `_`, without `__`.
- Use `--config <path>` for another config file.

### OAuth 2 (for example Sentry)

```jsonc
"sentry": {
  "type": "http",
  "url": "https://mcp.sentry.dev/mcp",
  "oauth": {}          // optional: scopes, clientId, clientSecret, callbackPort
}
```

```sh
toolward auth login sentry    # opens the browser, stores the tokens in the Keychain
toolward auth logout sentry
```

`serve` never opens a browser. It reads the stored tokens and refreshes them. If no login exists, the error says to run `toolward auth login <server>`. `clientSecret` may only be `${keychain:...}`, needs `clientId`, and `oauth` cannot be used together with `headers`. The tokens live in the account `oauth.<server>`, a name reserved for logins.

### Import an existing mcp.json

```sh
toolward import .mcp.json            # show the plan, change nothing
toolward import .mcp.json --apply    # store secrets, write the toolward config
```

Env and header values whose names look like secrets (`*_TOKEN`, `*_KEY`, `*_PASS`, `Authorization`, ...) move to the Keychain. A server with a secret in its `args` or `url`, with an unsupported `${...}` reference, or of type `sse`, is skipped with a reason. Nothing is changed in the source file, and **it still holds your plaintext tokens**: rotate them, then delete them from it. Comments in an existing toolward config are lost when it is merged.

## Threat model

toolward protects against an agent (or a prompt injection) **reading a secret from a file or from the config**. It does not make the agent trustworthy.

| Covered | Not covered |
| --- | --- |
| No secret in `mcp.json` or the toolward config | An upstream that is malicious, or that is told to leak (it receives the secret by design) |
| Secrets not in argv, stdout or logs (only account names are logged) | An agent that can run shell commands as you: it can run `security find-generic-password` |
| Results, resources, prompts and errors from upstreams have known secrets replaced by `[REDACTED]` | A secret an upstream transforms in a way not listed below |

Masking matches the secret as is, JSON-escaped, URL-encoded, base64 (any alignment) and per line for multi-line secrets, also in object keys. It is best effort:

- Secrets shorter than 4 characters are not masked.
- Tool, resource and prompt **lists** are not masked.
- Masking works on the final text. A secret split across two results, or hashed or re-encoded by the upstream, is not found.
- If a result cannot be inspected, the call fails instead of passing it on unchecked.

### Recommended hardening

Keep the agent from reading the secret files and the credential store directly. In Claude Code `settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.config/toolward/**)",
      "Bash(security *)",
      "Bash(toolward secret *)",
      "Bash(toolward auth *)",
      "Bash(toolward import *)"
    ]
  }
}
```

The toolward config holds only references, but it also lists your accounts. Keep plaintext `mcp.json` files out of the project after an import.

## Limits

- Resource templates are not forwarded, and URIs inside resource links are not rewritten.
- A server that fails to start is left out of `tools/list`; `toolward check --tools` shows why.
- Several `serve` processes can refresh the same OAuth token at once.

## Development

```sh
cargo fmt
cargo clippy --all-targets --locked -- -D warnings
cargo build --examples            # the integration tests start examples/fake_upstream
cargo nextest run --locked        # tests; cargo test --doc runs the doctests
cargo deny check                  # advisories and licenses
```

The Rust version is pinned in `rust-toolchain.toml`. See [ARCHITECTURE.md](ARCHITECTURE.md) for how the code is organized.

## License

MIT
