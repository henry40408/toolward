//! Moves the plaintext secrets of an existing `mcp.json` into the credential
//! store and produces the matching toolward config.
//!
//! Only environment variables and HTTP headers whose *names* look like
//! secrets are moved. Nothing here prints or logs a secret value.

use std::collections::BTreeSet;
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
    if crate::store::RESERVED_PREFIXES
        .iter()
        .any(|p| out.starts_with(p))
    {
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

    /// Plans one server. `Err` carries the reason it is left out.
    fn plan_server(&mut self, name: &str, server: Value) -> Result<Map<String, Value>, String> {
        let Value::Object(mut server) = server else {
            return Err("not an object".into());
        };
        if server.get("type").and_then(Value::as_str) == Some("sse") {
            return Err("SSE servers are not supported".into());
        }
        if server.contains_key("oauth") {
            return Err("already has an \"oauth\" setting".into());
        }
        if let Some(reason) = inline_secret(&server) {
            return Err(format!(
                "{reason}; move it into env by hand, then import again"
            ));
        }
        let (moves, secrets, notes) = (self.moves.len(), self.secrets.len(), self.notes.len());
        if let Some(Value::Object(env)) = server.get_mut("env") {
            self.extract_secrets(name, "env", env);
        }
        if let Some(Value::Object(headers)) = server.get_mut("headers") {
            self.extract_secrets(name, "header", headers);
        }
        // A server toolward cannot load (for example one with a foreign
        // ${...} reference) is left out whole, and its moves are undone.
        let mut single_server = Map::new();
        single_server.insert(name.to_owned(), Value::Object(server.clone()));
        let mut root = Map::new();
        root.insert("mcpServers".into(), Value::Object(single_server));
        if let Err(err) = Config::parse(&Value::Object(root).to_string()) {
            self.moves.truncate(moves);
            self.secrets.truncate(secrets);
            self.notes.truncate(notes);
            return Err(safe_error(&err));
        }
        Ok(server)
    }

    /// Replaces the secret-looking string values of `table`.
    fn extract_secrets(&mut self, server: &str, kind: &str, table: &mut Map<String, Value>) {
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
        match planner.plan_server(&name, server) {
            Ok(server) => {
                out.insert(name, Value::Object(server));
            }
            Err(reason) => skipped.push(format!("{name}: {reason}")),
        }
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

/// Every account named by a `${keychain:...}` reference inside `value`.
fn collect_refs(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => out.extend(crate::interpolate::references(text).unwrap_or_default()),
        Value::Array(items) => items.iter().for_each(|v| collect_refs(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_refs(v, out)),
        _ => {}
    }
}

/// Picks the account that will hold each secret: the planned name, or the
/// next free `<name>-2`, `-3`, ... when that account is taken. An account is
/// taken when it holds a different secret or the existing config refers to it.
/// An account that already holds the same secret is reused. Returns, per
/// secret, the account and whether this run has to create it.
fn choose_accounts(
    plan: &Plan,
    store: &dyn CredentialStore,
    refs: &BTreeSet<String>,
) -> Result<Vec<(String, bool)>> {
    let planned: BTreeSet<&str> = plan.secrets.iter().map(|(a, _)| a.as_str()).collect();
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    let mut chosen = Vec::new();
    for (wanted, secret) in &plan.secrets {
        let mut n = 1u32;
        loop {
            let candidate = if n == 1 {
                wanted.clone()
            } else {
                format!("{wanted}-{n}")
            };
            n += 1;
            if n > 10_000 {
                bail!("no free account name found for {wanted:?}");
            }
            let free_name = !claimed.contains(&candidate)
                && !refs.contains(&candidate)
                && (candidate == *wanted || !planned.contains(candidate.as_str()));
            if !free_name {
                continue;
            }
            validate_user_account(&candidate)?;
            match store.get(&candidate)? {
                None => chosen.push((candidate.clone(), true)),
                Some(current) if current == *secret => chosen.push((candidate.clone(), false)),
                Some(_) => continue,
            }
            claimed.insert(candidate);
            break;
        }
    }
    Ok(chosen)
}

/// Points the value that `moved` describes at `new` instead of `moved.account`.
fn retarget(servers: &mut Map<String, Value>, moved: &Move, new: &str) {
    let Some((kind, key)) = moved.place.split_once(' ') else {
        return;
    };
    let kind = if kind == "header" { "headers" } else { kind };
    if let Some(Value::String(text)) = servers
        .get_mut(&moved.server)
        .and_then(|s| s.get_mut(kind))
        .and_then(|t| t.get_mut(key))
    {
        *text = text.replace(
            &format!("${{keychain:{}}}", moved.account),
            &format!("${{keychain:{new}}}"),
        );
    }
}

/// Deletes the accounts this run created. Returns the ones that stayed.
fn roll_back(store: &dyn CredentialStore, created: &[String]) -> Vec<String> {
    created
        .iter()
        .filter(|account| store.delete(account).is_err())
        .cloned()
        .collect()
}

/// Reads the config at `path` as a JSON object. A missing file or `null` is empty.
fn read_existing_document(path: &Path) -> Result<Map<String, Value>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(err) => return Err(err).with_context(|| format!("cannot read {}", path.display())),
    };
    let value = jsonc_parser::parse_to_serde_value::<Value>(&text, &Default::default())
        .map_err(|_| anyhow::anyhow!("the existing config is not valid JSON"))?;
    match value {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Map::new()),
        _ => bail!("the existing config is not a JSON object"),
    }
}

/// Stores the secrets `chosen` marks as new, then replaces the file at `path`
/// with `text`. If either step fails, the accounts this run created are deleted.
fn store_and_replace(
    store: &dyn CredentialStore,
    path: &Path,
    text: &str,
    chosen: &[(String, bool)],
    secrets: &[(String, String)],
) -> Result<()> {
    // Write through a symlink instead of replacing it.
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let temp = path.with_extension("json.tmp");
    let mut created: Vec<String> = Vec::new();
    let result = write_private(&temp, text)
        .with_context(|| format!("cannot write {}", temp.display()))
        .and_then(|()| {
            for ((account, needs_set), (_, secret)) in chosen.iter().zip(secrets) {
                if *needs_set {
                    // A failed `set` may still have created the account.
                    created.push(account.clone());
                    store
                        .set(account, secret)
                        .with_context(|| format!("cannot store {account}"))?;
                }
            }
            std::fs::rename(&temp, &path)
                .with_context(|| format!("cannot replace {}", path.display()))
        });
    let Err(err) = result else {
        return Ok(());
    };
    let _ = std::fs::remove_file(&temp);
    let left = roll_back(store, &created);
    if left.is_empty() {
        return Err(err);
    }
    bail!(
        "{err:#}; also could not remove the stored account(s): {}",
        left.join(", ")
    );
}

/// Stores the secrets and writes the servers into the config file at `path`,
/// merging with what is there (comments in an existing file are lost).
/// Nothing is written unless every check passes first. If storing a secret or
/// replacing the file fails, the accounts this run created are deleted again.
///
/// An account that holds a different secret is not overwritten: the secret
/// goes to the next free name (`<name>-2`, ...), and `plan` is updated to say
/// so, so `report` shows the names that were really used.
///
/// Limitation: the check (`get`) and the write (`set`) are not atomic, so a
/// concurrent writer to the same account can still be overwritten, or have its
/// new account deleted again by the rollback.
pub fn apply(plan: &mut Plan, store: &dyn CredentialStore, path: &Path) -> Result<()> {
    for (account, _) in &plan.secrets {
        validate_user_account(account)?;
    }
    let mut document = read_existing_document(path)?;
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
    let mut refs = BTreeSet::new();
    existing.values().for_each(|v| collect_refs(v, &mut refs));
    let chosen = choose_accounts(plan, store, &refs)?;

    let mut servers = plan.servers.clone();
    let mut moves = plan.moves.clone();
    for (moved, (account, _)) in moves.iter_mut().zip(&chosen) {
        if moved.account != *account {
            retarget(&mut servers, moved, account);
            moved.account.clone_from(account);
        }
    }
    existing.extend(servers.clone());
    let text = serde_json::to_string_pretty(&Value::Object(document))? + "\n";
    // The merged file must load, or nothing is stored.
    Config::parse(&text)
        .map_err(|err| anyhow::anyhow!("the merged config is not valid: {}", safe_error(&err)))?;

    store_and_replace(store, path, &text, &chosen, &plan.secrets)?;
    for ((account, _), (slot, _)) in chosen.iter().zip(plan.secrets.iter_mut()) {
        slot.clone_from(account);
    }
    plan.servers = servers;
    plan.moves = moves;
    Ok(())
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
    for moved in &plan.moves {
        writeln!(
            out,
            "{verb} {}: {} -> ${{keychain:{}}}",
            moved.server, moved.place, moved.account
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
            "\nNote: with --apply, an account name gets a numeric suffix (-2, -3, ...) \
             if that name already holds a different value."
        )?;
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
        apply(&mut plan(SOURCE).unwrap(), &store, &path).unwrap();
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
        let err = apply(&mut plan(SOURCE).unwrap(), &store, &path).unwrap_err();
        assert!(err.to_string().contains("already has a server"), "{err}");
        assert_eq!(store.get("db-db_token").unwrap(), None);
    }

    /// Fails the Nth `set` (1-based) and, optionally, every `delete`.
    struct FailingStore {
        inner: MemoryStore,
        fail_set_at: usize,
        fail_delete: bool,
        sets: std::sync::atomic::AtomicUsize,
    }

    impl FailingStore {
        fn new(inner: MemoryStore, fail_set_at: usize, fail_delete: bool) -> Self {
            Self {
                inner,
                fail_set_at,
                fail_delete,
                sets: Default::default(),
            }
        }
    }

    impl CredentialStore for FailingStore {
        fn get(&self, account: &str) -> Result<Option<String>, crate::store::StoreError> {
            self.inner.get(account)
        }
        fn set(&self, account: &str, secret: &str) -> Result<(), crate::store::StoreError> {
            let n = self.sets.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if n == self.fail_set_at {
                return Err(crate::store::StoreError::Backend("denied".into()));
            }
            self.inner.set(account, secret)
        }
        fn delete(&self, account: &str) -> Result<bool, crate::store::StoreError> {
            if self.fail_delete {
                return Err(crate::store::StoreError::Backend("denied".into()));
            }
            self.inner.delete(account)
        }
    }

    const ORIGINAL: &str = r#"{"mcpServers": {"keep": {"command": "x"}}}"#;

    #[test]
    fn failed_set_rolls_back_only_new_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, ORIGINAL).unwrap();
        // db-db_token already holds the same value, so it is not ours to delete.
        let inner = MemoryStore::with(&[("db-db_token", "tok-SECRET2")]);
        let store = FailingStore::new(inner, 1, false);
        let mut plan = plan(SOURCE).unwrap();
        // Order is db (existing, reused), gh (the failing set).
        let err = apply(&mut plan, &store, &path).unwrap_err();
        assert!(format!("{err:#}").contains("denied"), "{err:#}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ORIGINAL);
        assert!(!dir.path().join("config.json.tmp").exists());
        assert_eq!(
            store.get("db-db_token").unwrap().as_deref(),
            Some("tok-SECRET2")
        );
        assert_eq!(store.get("gh-authorization").unwrap(), None);
    }

    #[test]
    fn failure_after_a_set_deletes_what_this_run_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, ORIGINAL).unwrap();
        let store = FailingStore::new(MemoryStore::with(&[("other", "o-SECRET9")]), 2, false);
        let err = apply(&mut plan(SOURCE).unwrap(), &store, &path).unwrap_err();
        assert!(format!("{err:#}").contains("denied"), "{err:#}");
        assert_eq!(store.get("db-db_token").unwrap(), None);
        assert_eq!(store.get("gh-authorization").unwrap(), None);
        assert_eq!(store.get("other").unwrap().as_deref(), Some("o-SECRET9"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ORIGINAL);
        assert!(!dir.path().join("config.json.tmp").exists());
    }

    #[test]
    fn rollback_failure_is_reported_by_account_name_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let store = FailingStore::new(MemoryStore::new(), 2, true);
        let err = apply(&mut plan(SOURCE).unwrap(), &store, &path).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("denied"), "{text}");
        assert!(text.contains("db-db_token"), "{text}");
        assert!(!text.contains("SECRET"), "{text}");
        assert!(!path.exists());
        assert!(!dir.path().join("config.json.tmp").exists());
    }

    #[test]
    fn failed_rename_deletes_what_this_run_created() {
        /// Creates a directory at the config path on every `set`, so the
        /// final rename fails after the secrets are stored.
        struct DirOnSet {
            inner: MemoryStore,
            dir: std::path::PathBuf,
        }
        impl CredentialStore for DirOnSet {
            fn get(&self, account: &str) -> Result<Option<String>, crate::store::StoreError> {
                self.inner.get(account)
            }
            fn set(&self, account: &str, secret: &str) -> Result<(), crate::store::StoreError> {
                let _ = std::fs::create_dir(&self.dir);
                self.inner.set(account, secret)
            }
            fn delete(&self, account: &str) -> Result<bool, crate::store::StoreError> {
                self.inner.delete(account)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let store = DirOnSet {
            inner: MemoryStore::with(&[("other", "o-SECRET9"), ("db-db_token", "tok-SECRET2")]),
            dir: path.clone(),
        };
        assert!(!path.exists());
        let err = apply(&mut plan(SOURCE).unwrap(), &store, &path).unwrap_err();
        assert!(err.to_string().contains("cannot replace"), "{err:#}");
        // gh-authorization was created by this run; the other two were not.
        assert_eq!(store.get("gh-authorization").unwrap(), None);
        assert_eq!(store.get("other").unwrap().as_deref(), Some("o-SECRET9"));
        assert_eq!(
            store.get("db-db_token").unwrap().as_deref(),
            Some("tok-SECRET2")
        );
        assert!(!dir.path().join("config.json.tmp").exists());
    }

    #[test]
    fn a_bearer_header_is_retargeted_keeping_its_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let store = MemoryStore::with(&[("gh-authorization", "different-SECRET")]);
        let mut plan = plan(SOURCE).unwrap();
        apply(&mut plan, &store, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("Bearer ${keychain:gh-authorization-2}"),
            "{text}"
        );
        assert!(!text.contains("${keychain:gh-authorization}"), "{text}");
        assert!(
            plan.config_json()
                .to_string()
                .contains("Bearer ${keychain:gh-authorization-2}")
        );
        assert_eq!(
            store.get("gh-authorization").unwrap().as_deref(),
            Some("different-SECRET")
        );
    }

    #[test]
    fn a_suffix_that_another_entry_wants_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        // Both keys map to s-a_token; the planner names them s-a_token and s-a_token-2.
        let source = r#"{"mcpServers": {"s": {"command": "y",
            "env": {"A_TOKEN": "tok-SECRET4", "a_token": "tok-SECRET5"}}}}"#;
        let store = MemoryStore::with(&[("s-a_token", "different-SECRET")]);
        let mut plan = plan(source).unwrap();
        let wanted: Vec<&str> = plan.moves.iter().map(|m| m.account.as_str()).collect();
        assert_eq!(wanted, ["s-a_token", "s-a_token-2"]);
        apply(&mut plan, &store, &path).unwrap();
        let accounts: Vec<&str> = plan.moves.iter().map(|m| m.account.as_str()).collect();
        assert_eq!(accounts, ["s-a_token-3", "s-a_token-2"]);
        assert_eq!(
            store.get("s-a_token-3").unwrap().as_deref(),
            Some("tok-SECRET4")
        );
        assert_eq!(
            store.get("s-a_token-2").unwrap().as_deref(),
            Some("tok-SECRET5")
        );
    }

    #[test]
    fn a_suffixed_account_with_the_same_value_is_reused_and_kept_on_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let inner = MemoryStore::with(&[
            ("gh-authorization", "different-SECRET"),
            ("gh-authorization-2", "ghp_SECRET1"),
        ]);
        // Only db-db_token needs a set; make it fail.
        let store = FailingStore::new(inner, 1, false);
        let err = apply(&mut plan(SOURCE).unwrap(), &store, &path).unwrap_err();
        assert!(format!("{err:#}").contains("denied"), "{err:#}");
        assert_eq!(store.sets.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            store.get("gh-authorization-2").unwrap().as_deref(),
            Some("ghp_SECRET1")
        );
        assert_eq!(
            store.get("gh-authorization").unwrap().as_deref(),
            Some("different-SECRET")
        );

        // On success the reused account is referenced and no extra account exists.
        let store = MemoryStore::with(&[
            ("gh-authorization", "different-SECRET"),
            ("gh-authorization-2", "ghp_SECRET1"),
        ]);
        apply(&mut plan(SOURCE).unwrap(), &store, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("${keychain:gh-authorization-2}"), "{text}");
        assert_eq!(store.get("gh-authorization-3").unwrap(), None);
    }

    #[test]
    fn plan_is_unchanged_after_a_failed_apply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let store = FailingStore::new(
            MemoryStore::with(&[("gh-authorization", "different-SECRET")]),
            2,
            false,
        );
        let mut plan = plan(SOURCE).unwrap();
        let json = plan.config_json();
        let moves = plan.moves.clone();
        let secrets = plan.secrets.clone();
        assert!(apply(&mut plan, &store, &path).is_err());
        assert_eq!(plan.config_json(), json);
        assert_eq!(plan.moves, moves);
        assert_eq!(plan.secrets, secrets);
    }

    #[test]
    fn a_taken_account_gets_a_suffixed_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        // The existing config refers to db-db_token-2, so it is not free either.
        std::fs::write(
            &path,
            r#"{"mcpServers": {"keep": {"command": "x", "env": {"A": "${keychain:db-db_token-2}"}}}}"#,
        )
        .unwrap();
        let store = MemoryStore::with(&[("db-db_token", "different-SECRET")]);
        let mut plan = plan(SOURCE).unwrap();
        apply(&mut plan, &store, &path).unwrap();

        assert_eq!(
            store.get("db-db_token").unwrap().as_deref(),
            Some("different-SECRET")
        );
        assert_eq!(
            store.get("db-db_token-3").unwrap().as_deref(),
            Some("tok-SECRET2")
        );
        assert_eq!(store.get("db-db_token-2").unwrap(), None);
        let accounts: Vec<&str> = plan.moves.iter().map(|m| m.account.as_str()).collect();
        assert_eq!(accounts, ["db-db_token-3", "gh-authorization"]);
        let mut out = Vec::new();
        report(&plan, true, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("${keychain:db-db_token-3}"), "{out}");

        // The written config and the store expand back to the original values.
        let config = Config::load(&path).unwrap();
        let env = config.mcp_servers["db"].env.clone();
        let token = crate::interpolate::expand(&env["DB_TOKEN"], &store).unwrap();
        assert_eq!(token, "tok-SECRET2");
        let headers = config.mcp_servers["gh"].headers.clone();
        let auth = crate::interpolate::expand(&headers["Authorization"], &store).unwrap();
        assert_eq!(auth, "Bearer ghp_SECRET1");
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
        let err = apply(&mut plan(source).unwrap(), &store, &path).unwrap_err();
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
        apply(&mut plan(SOURCE).unwrap(), &MemoryStore::new(), &path).unwrap();
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
        assert_eq!(
            account_name("oauth-client.x", "T"),
            "imported-oauth-client.x-t"
        );
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
