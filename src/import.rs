//! Moves the plaintext secrets of an existing `mcp.json` into the credential
//! store and produces the matching toolward config.
//!
//! Only environment variables and HTTP headers whose *names* look like
//! secrets are moved. Nothing here prints or logs a secret value.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

use crate::config::Config;
use crate::store::{CredentialStore, validate_user_account};

/// A name containing one of these (any case) holds a secret.
const SECRET_WORDS: &[&str] = &[
    "token",
    "secret",
    "key",
    "password",
    "passwd",
    "auth",
    "credential",
    "cookie",
    "signature",
    "bearer",
];

/// Short words that only count as a whole word (`PAT` but not `PATH`).
const SECRET_TOKENS: &[&str] = &["pass", "pwd", "pat", "dsn", "jwt", "session", "private"];

/// Value prefixes of well-known credentials.
const SECRET_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "sk-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "glpat-",
    "AKIA",
];

fn looks_secret(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| name.contains(word))
        || name
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|part| SECRET_TOKENS.contains(&part))
}

fn has_secret_prefix(value: &str) -> bool {
    SECRET_PREFIXES.iter().any(|p| value.starts_with(p))
}

/// Why a field that cannot hold a reference carries a secret, if it does.
fn inline_secret(server: &Map<String, Value>) -> Option<String> {
    if let Some(url) = server.get("url").and_then(Value::as_str) {
        let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return Some("its url contains a user name or password".into());
        }
        if let Some((_, query)) = url.split_once('?')
            && query.split('&').any(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                looks_secret(key) || has_secret_prefix(value)
            })
        {
            return Some("its url contains a secret in the query".into());
        }
    }
    let args = server.get("args").and_then(Value::as_array)?;
    for arg in args.iter().filter_map(Value::as_str) {
        let (flag, value) = arg.split_once('=').unwrap_or((arg, ""));
        if flag.starts_with("--") && looks_secret(flag) {
            return Some(format!("argument {flag} looks like it holds a secret"));
        }
        if has_secret_prefix(arg) || has_secret_prefix(value) {
            return Some("an argument looks like a secret".into());
        }
    }
    None
}

/// A config error without the text that caused it (serde quotes values).
fn safe_error(err: &crate::config::ConfigError) -> String {
    match err {
        crate::config::ConfigError::Shape(_) => "a field has the wrong type".into(),
        other => other.to_string(),
    }
}

/// One value that moves into the credential store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    pub server: String,
    /// For example `env GITHUB_TOKEN` or `header Authorization`.
    pub place: String,
    pub account: String,
}

/// What an import would do. It holds secret values, so it has no `Debug`.
pub struct Plan {
    /// The `mcpServers` entries, with references where secrets were.
    servers: Map<String, Value>,
    pub moves: Vec<Move>,
    secrets: Vec<(String, String)>,
    /// Servers left out, with the reason.
    pub skipped: Vec<String>,
    /// Things the user should look at by hand.
    pub notes: Vec<String>,
}

impl Plan {
    /// The toolward config that results, without any secret.
    pub fn config_json(&self) -> Value {
        let mut root = Map::new();
        root.insert("mcpServers".into(), Value::Object(self.servers.clone()));
        Value::Object(root)
    }
}

/// Turns free text into an account name.
fn account_name(server: &str, key: &str) -> String {
    let raw = format!("{server}-{key}").to_ascii_lowercase();
    let mut out = String::new();
    for c in raw.chars() {
        let c = if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            c
        } else {
            '-'
        };
        out.push(c);
    }
    if out.starts_with("oauth.") {
        out.insert_str(0, "imported-");
    }
    out
}

/// Splits `Bearer abc` into (`Bearer `, `abc`). Other values have no scheme.
fn split_scheme(value: &str) -> (&str, &str) {
    for scheme in ["Bearer ", "Basic ", "Token "] {
        if value.len() > scheme.len() && value[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return value.split_at(scheme.len());
        }
    }
    ("", value)
}

struct Planner {
    moves: Vec<Move>,
    secrets: Vec<(String, String)>,
    notes: Vec<String>,
    used: BTreeSet<String>,
}

impl Planner {
    fn unique(&mut self, wanted: String) -> String {
        let mut account = wanted.clone();
        let mut n = 2;
        while !self.used.insert(account.clone()) {
            account = format!("{wanted}-{n}");
            n += 1;
        }
        account
    }

    /// Replaces the secret-looking string values of `table`.
    fn table(&mut self, server: &str, kind: &str, table: &mut Map<String, Value>) {
        for (key, value) in table.iter_mut() {
            let Some(text) = value.as_str() else { continue };
            if text.is_empty() || !(looks_secret(key) || has_secret_prefix(text)) {
                continue;
            }
            if text.contains("${") {
                self.notes.push(format!(
                    "{server}: {kind} {key} contains a ${{...}} reference and was left as is; \
                     toolward only understands ${{keychain:...}}"
                ));
                continue;
            }
            let (scheme, secret) = split_scheme(text);
            let account = self.unique(account_name(server, key));
            let replacement = format!("{scheme}${{keychain:{account}}}");
            self.secrets.push((account.clone(), secret.to_owned()));
            self.moves.push(Move {
                server: server.to_owned(),
                place: format!("{kind} {key}"),
                account,
            });
            *value = Value::String(replacement);
        }
    }
}

/// Reads a Claude-style `mcp.json` and plans the move.
pub fn plan(source: &str) -> Result<Plan> {
    let root = jsonc_parser::parse_to_serde_value::<Value>(source, &Default::default())
        .map_err(|_| anyhow::anyhow!("the file is not valid JSON"))?;
    let Some(Value::Object(servers)) = root.get("mcpServers").cloned() else {
        bail!("the file has no \"mcpServers\" object");
    };

    let mut planner = Planner {
        moves: Vec::new(),
        secrets: Vec::new(),
        notes: Vec::new(),
        used: BTreeSet::new(),
    };
    let mut out = Map::new();
    let mut skipped = Vec::new();
    for (name, server) in servers {
        let Value::Object(mut server) = server else {
            skipped.push(format!("{name}: not an object"));
            continue;
        };
        if server.get("type").and_then(Value::as_str) == Some("sse") {
            skipped.push(format!("{name}: SSE servers are not supported"));
            continue;
        }
        if server.contains_key("oauth") {
            skipped.push(format!("{name}: already has an \"oauth\" setting"));
            continue;
        }
        if let Some(reason) = inline_secret(&server) {
            skipped.push(format!(
                "{name}: {reason}; move it into env by hand, then import again"
            ));
            continue;
        }
        let (moves, secrets, notes) = (
            planner.moves.len(),
            planner.secrets.len(),
            planner.notes.len(),
        );
        if let Some(Value::Object(env)) = server.get_mut("env") {
            planner.table(&name, "env", env);
        }
        if let Some(Value::Object(headers)) = server.get_mut("headers") {
            planner.table(&name, "header", headers);
        }
        // A server toolward cannot load (for example one with a foreign
        // ${...} reference) is left out whole, and its moves are undone.
        let mut one = Map::new();
        one.insert(name.clone(), Value::Object(server.clone()));
        let mut root = Map::new();
        root.insert("mcpServers".into(), Value::Object(one));
        if let Err(err) = Config::parse(&Value::Object(root).to_string()) {
            planner.moves.truncate(moves);
            planner.secrets.truncate(secrets);
            planner.notes.truncate(notes);
            skipped.push(format!("{name}: {}", safe_error(&err)));
            continue;
        }
        out.insert(name, Value::Object(server));
    }

    let plan = Plan {
        servers: out,
        moves: planner.moves,
        secrets: planner.secrets,
        skipped,
        notes: planner.notes,
    };
    // The result must be a config toolward accepts, or nothing is stored.
    Config::parse(&plan.config_json().to_string()).map_err(|err| {
        anyhow::anyhow!("the imported servers are not valid: {}", safe_error(&err))
    })?;
    Ok(plan)
}

/// Stores the secrets and writes the servers into the config file at `path`,
/// merging with what is there (comments in an existing file are lost).
/// Nothing is written unless every check passes first.
pub fn apply(plan: &Plan, store: &dyn CredentialStore, path: &Path) -> Result<()> {
    for (account, _) in &plan.secrets {
        validate_user_account(account)?;
    }
    let mut document = match std::fs::read_to_string(path) {
        Ok(text) => {
            let value = jsonc_parser::parse_to_serde_value::<Value>(&text, &Default::default())
                .map_err(|_| anyhow::anyhow!("the existing config is not valid JSON"))?;
            match value {
                Value::Object(map) => map,
                Value::Null => Map::new(),
                _ => bail!("the existing config is not a JSON object"),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Map::new(),
        Err(err) => return Err(err).with_context(|| format!("cannot read {}", path.display())),
    };
    let existing = document
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(existing) = existing else {
        bail!("\"mcpServers\" in the existing config is not an object");
    };
    for name in plan.servers.keys() {
        if existing.contains_key(name) {
            bail!("the config already has a server named {name:?}");
        }
    }
    let mut stale: BTreeMap<&str, ()> = BTreeMap::new();
    for (account, secret) in &plan.secrets {
        if let Some(current) = store.get(account)?
            && current != *secret
        {
            stale.insert(account, ());
        }
    }
    if let Some((account, _)) = stale.iter().next() {
        bail!(
            "account {account:?} already holds a different secret; \
             run `toolward secret delete {account}` first"
        );
    }

    existing.extend(plan.servers.clone());
    let text = serde_json::to_string_pretty(&Value::Object(document))? + "\n";
    // The merged file must load, or nothing is stored.
    Config::parse(&text)
        .map_err(|err| anyhow::anyhow!("the merged config is not valid: {}", safe_error(&err)))?;

    // Write through a symlink instead of replacing it.
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let temp = path.with_extension("json.tmp");
    let result = write_private(&temp, &text)
        .with_context(|| format!("cannot write {}", temp.display()))
        .and_then(|()| {
            for (account, secret) in &plan.secrets {
                store.set(account, secret)?;
            }
            std::fs::rename(&temp, &path)
                .with_context(|| format!("cannot replace {}", path.display()))
        });
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Creates `path` readable by the owner only.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

/// Prints the plan. Never prints a secret value.
pub fn report(plan: &Plan, applied: bool, out: &mut dyn std::io::Write) -> Result<()> {
    let verb = if applied { "moved" } else { "would move" };
    for m in &plan.moves {
        writeln!(
            out,
            "{verb} {}: {} -> ${{keychain:{}}}",
            m.server, m.place, m.account
        )?;
    }
    if plan.moves.is_empty() {
        writeln!(out, "no secret-looking env or header values found")?;
    }
    for line in &plan.skipped {
        writeln!(out, "skipped {line}")?;
    }
    for line in &plan.notes {
        writeln!(out, "note: {line}")?;
    }
    if applied {
        writeln!(
            out,
            "\nNext: replace the servers in your mcp.json with one entry that runs \
             `toolward serve`, and rotate the tokens that were in that file."
        )?;
    } else {
        writeln!(
            out,
            "\nNothing was changed. Run again with --apply to do it."
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    const SOURCE: &str = r#"{
      // comments are fine
      "mcpServers": {
        "gh": {"type": "http", "url": "https://x/mcp",
               "headers": {"Authorization": "Bearer ghp_SECRET1", "X-Team": "red"}},
        "db": {"command": "db", "args": ["--port", "5"],
               "env": {"DB_TOKEN": "tok-SECRET2", "MODE": "fast"}},
        "ref": {"command": "r", "env": {"API_KEY": "${API_KEY}"}},
        "arg": {"command": "a", "args": ["--password=hunter22"]},
        "url": {"url": "https://u:hunter23@h/mcp"},
        "bad": {"command": ["--token ghp_LEAKARGSTR"]},
        "old": {"type": "sse", "url": "https://y/sse"}
      }
    }"#;

    #[test]
    fn plans_moves_without_exposing_values() {
        let plan = plan(SOURCE).unwrap();
        let places: Vec<(&str, &str, &str)> = plan
            .moves
            .iter()
            .map(|m| (m.server.as_str(), m.place.as_str(), m.account.as_str()))
            .collect();
        assert_eq!(
            places,
            [
                ("db", "env DB_TOKEN", "db-db_token"),
                ("gh", "header Authorization", "gh-authorization"),
            ]
        );
        let json = plan.config_json().to_string();
        assert!(!json.contains("SECRET"), "{json}");
        assert!(
            json.contains("Bearer ${keychain:gh-authorization}"),
            "{json}"
        );
        assert!(json.contains("${keychain:db-db_token}"));
        assert!(json.contains("\"MODE\":\"fast\""));
        let notes = plan.notes.join("\n");
        assert_eq!(plan.skipped.len(), 5, "{:?}", plan.skipped);
        assert!(!notes.contains("hunter22"));
        let skipped = plan.skipped.join("\n");
        assert!(
            !skipped.contains("LEAK") && !skipped.contains("hunter2"),
            "{skipped}"
        );
        let mut out = Vec::new();
        report(&plan, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            !out.contains("SECRET") && !out.contains("hunter22"),
            "{out}"
        );
    }

    #[test]
    fn apply_stores_secrets_and_merges_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"mcpServers": {"keep": {"command": "x"}}}"#).unwrap();
        let store = MemoryStore::new();
        apply(&plan(SOURCE).unwrap(), &store, &path).unwrap();
        assert_eq!(
            store.get("gh-authorization").unwrap().as_deref(),
            Some("ghp_SECRET1")
        );
        assert_eq!(
            store.get("db-db_token").unwrap().as_deref(),
            Some("tok-SECRET2")
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("SECRET"), "{text}");
        let config = Config::parse(&text).unwrap();
        let names: Vec<&String> = config.mcp_servers.keys().collect();
        assert_eq!(names, ["db", "gh", "keep"]);
    }

    #[test]
    fn apply_refuses_conflicts_before_changing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"mcpServers": {"gh": {"command": "x"}}}"#).unwrap();
        let store = MemoryStore::new();
        let err = apply(&plan(SOURCE).unwrap(), &store, &path).unwrap_err();
        assert!(err.to_string().contains("already has a server"), "{err}");
        assert_eq!(store.get("db-db_token").unwrap(), None);

        std::fs::remove_file(&path).unwrap();
        store.set("gh-authorization", "different").unwrap();
        let err = apply(&plan(SOURCE).unwrap(), &store, &path).unwrap_err();
        assert!(err.to_string().contains("different secret"), "{err}");
        assert!(!err.to_string().contains("different\""));
        assert_eq!(store.get("db-db_token").unwrap(), None);
        assert!(!path.exists());
    }

    #[test]
    fn detects_more_names_and_values() {
        for name in ["DB_PASS", "MYSQL_PWD", "GH_PAT", "SENTRY_DSN", "api-key"] {
            assert!(looks_secret(name), "{name}");
        }
        for name in ["PATH", "MODE", "HOME", "PASSIVE"] {
            assert!(!looks_secret(name), "{name}");
        }
        assert!(has_secret_prefix("ghp_abc"));
    }

    #[test]
    fn apply_checks_the_merged_config_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"mcpServers": {"a-b": {"command": "x"}}}"#).unwrap();
        let store = MemoryStore::new();
        let source =
            r#"{"mcpServers": {"a_b": {"command": "y", "env": {"T_TOKEN": "tok-SECRET3"}}}}"#;
        let err = apply(&plan(source).unwrap(), &store, &path).unwrap_err();
        assert!(err.to_string().contains("merged"), "{err}");
        assert_eq!(store.get("a_b-t_token").unwrap(), None);
        assert!(!dir.path().join("config.json.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn written_config_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        apply(&plan(SOURCE).unwrap(), &MemoryStore::new(), &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn rejects_files_without_servers() {
        assert!(plan("{}").is_err());
        assert!(plan("not json").is_err());
    }

    #[test]
    fn account_names_are_valid_and_unique() {
        assert_eq!(account_name("My Server", "API/KEY"), "my-server-api-key");
        assert_eq!(account_name("oauth.x", "T"), "imported-oauth.x-t");
        let mut planner = Planner {
            moves: vec![],
            secrets: vec![],
            notes: vec![],
            used: BTreeSet::new(),
        };
        assert_eq!(planner.unique("a".into()), "a");
        assert_eq!(planner.unique("a".into()), "a-2");
    }
}
