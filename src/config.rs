//! Config file: a JSON(C) document using the de facto `mcpServers` layout that
//! Claude Code, Cursor, Claude Desktop and others share, so existing entries
//! can be pasted in and their secrets replaced with `${keychain:<account>}`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::interpolate;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid JSON: {0}")]
    Syntax(String),
    #[error("invalid config: {0}")]
    Shape(#[from] serde_json::Error),
    #[error("config file is empty")]
    Empty,
    #[error("server {name:?}: {reason}")]
    Server { name: String, reason: String },
    #[error("server {name:?}: {source}")]
    Reference {
        name: String,
        source: interpolate::InterpolateError,
    },
    #[error("cannot determine the config directory: {0}")]
    NoConfigDir(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default)]
    pub mcp_servers: BTreeMap<String, ServerConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub url: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub oauth: Option<OAuthConfig>,
    /// Fields toolward does not use (`disabled`, `timeout`, ...) are kept, not rejected.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthConfig {
    #[serde(default)]
    pub scopes: Vec<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// How to reach an upstream, after validation.
#[derive(Debug)]
pub enum Transport<'a> {
    Stdio {
        command: &'a str,
        args: &'a [String],
        env: &'a BTreeMap<String, String>,
    },
    Http {
        url: &'a str,
        headers: &'a BTreeMap<String, String>,
        oauth: Option<&'a OAuthConfig>,
    },
}

impl ServerConfig {
    pub fn transport(&self) -> Result<Transport<'_>, String> {
        match (self.kind.as_deref(), &self.command, &self.url) {
            (None | Some("stdio"), Some(command), None) => {
                if !self.headers.is_empty() || self.oauth.is_some() {
                    return Err("'headers' and 'oauth' apply only to http servers".into());
                }
                Ok(Transport::Stdio {
                    command,
                    args: &self.args,
                    env: &self.env,
                })
            }
            (None | Some("http"), None, Some(url)) => {
                if !self.args.is_empty() || !self.env.is_empty() {
                    return Err("'args' and 'env' apply only to stdio servers".into());
                }
                Ok(Transport::Http {
                    url,
                    headers: &self.headers,
                    oauth: self.oauth.as_ref(),
                })
            }
            (Some(other @ ("stdio" | "http")), _, _) => {
                Err(format!("type {other:?} does not match the fields given"))
            }
            (Some(other), _, _) => Err(format!(
                "unsupported type {other:?}: expected \"stdio\" or \"http\""
            )),
            (None, Some(_), Some(_)) => Err("set either 'command' or 'url', not both".into()),
            (None, None, None) => Err("set either 'command' (stdio) or 'url' (http)".into()),
        }
    }

    /// Every string in which `${keychain:...}` references are expanded.
    fn interpolated_strings(&self) -> impl Iterator<Item = &str> {
        let oauth = self
            .oauth
            .iter()
            .flat_map(|o| o.client_id.iter().chain(o.client_secret.iter()));
        self.command
            .iter()
            .chain(self.url.iter())
            .chain(self.args.iter())
            .chain(self.env.values())
            .chain(self.headers.values())
            .chain(oauth)
            .map(String::as_str)
    }
}

/// True when a string anywhere inside `value` holds a `${keychain:...}` reference.
/// Used on fields toolward ignores, where a reference would silently go unexpanded.
fn contains_reference(value: &serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::String(text) => text.contains("${keychain:"),
        Value::Array(items) => items.iter().any(contains_reference),
        Value::Object(map) => map.values().any(contains_reference),
        _ => false,
    }
}

/// Server names become tool prefixes (`<name>__<tool>`), so `__` is reserved.
fn validate_name(name: &str) -> Result<(), String> {
    let charset_ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !charset_ok || name.contains("__") || name.starts_with('_') || name.ends_with('_') {
        return Err(
            "name must be ASCII letters, digits, '-' or '_', without '__' \
             and without a leading or trailing '_'"
                .into(),
        );
    }
    Ok(())
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let value =
            jsonc_parser::parse_to_serde_value::<serde_json::Value>(text, &Default::default())
                .map_err(|err| ConfigError::Syntax(err.to_string()))?;
        if value.is_null() {
            return Err(ConfigError::Empty);
        }
        let config: Config = serde_json::from_value(value)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (name, server) in &self.mcp_servers {
            let fail = |reason: String| ConfigError::Server {
                name: name.clone(),
                reason,
            };
            validate_name(name).map_err(fail)?;
            server.transport().map_err(fail)?;
            if let Some(command) = &server.command
                && !interpolate::references(command)
                    .unwrap_or_default()
                    .is_empty()
            {
                return Err(fail("'command' must not contain secret references".into()));
            }
            for (field, value) in &server.extra {
                if contains_reference(value) {
                    return Err(fail(format!(
                        "secret references are not supported in field {field:?}"
                    )));
                }
            }
            for text in server.interpolated_strings() {
                interpolate::references(text).map_err(|source| ConfigError::Reference {
                    name: name.clone(),
                    source,
                })?;
            }
        }
        Ok(())
    }

    /// Accounts referenced by each server, without reading any secret.
    pub fn references(&self) -> BTreeMap<&str, BTreeSet<String>> {
        self.mcp_servers
            .iter()
            .map(|(name, server)| {
                let accounts = server
                    .interpolated_strings()
                    .flat_map(|text| interpolate::references(text).unwrap_or_default())
                    .collect();
                (name.as_str(), accounts)
            })
            .collect()
    }
}

/// `~/.config/toolward/config.json` (XDG layout on macOS and Linux).
pub fn default_path() -> Result<PathBuf, ConfigError> {
    use etcetera::BaseStrategy;
    let strategy = etcetera::choose_base_strategy()
        .map_err(|err| ConfigError::NoConfigDir(err.to_string()))?;
    Ok(strategy.config_dir().join("toolward").join("config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      // JSONC comments and trailing commas are accepted
      "mcpServers": {
        "github": {
          "command": "npx",
          "args": ["-y", "server-github"],
          "env": { "TOKEN": "${keychain:github}", "LOG": "info" },
          "disabled": false,
        },
        "internal": {
          "type": "http",
          "url": "https://mcp.example.com/mcp",
          "headers": { "Authorization": "Bearer ${keychain:internal}" }
        },
        "sentry": {
          "type": "http",
          "url": "https://mcp.sentry.dev/mcp",
          "oauth": { "scopes": ["org:read"], "clientSecret": "${keychain:sentry-cs}" }
        }
      }
    }"#;

    fn err(text: &str) -> String {
        Config::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn parses_sample() {
        let config = Config::parse(SAMPLE).unwrap();
        assert_eq!(config.mcp_servers.len(), 3);
        let github = &config.mcp_servers["github"];
        assert!(matches!(
            github.transport(),
            Ok(Transport::Stdio { command: "npx", .. })
        ));
        assert!(github.extra.contains_key("disabled"));
        assert!(matches!(
            config.mcp_servers["sentry"].transport(),
            Ok(Transport::Http { oauth: Some(_), .. })
        ));
    }

    #[test]
    fn collects_references_per_server() {
        let config = Config::parse(SAMPLE).unwrap();
        let refs = config.references();
        assert_eq!(refs["github"], BTreeSet::from(["github".to_owned()]));
        assert_eq!(refs["internal"], BTreeSet::from(["internal".to_owned()]));
        assert_eq!(refs["sentry"], BTreeSet::from(["sentry-cs".to_owned()]));
    }

    #[test]
    fn empty_servers_is_valid() {
        assert!(Config::parse("{}").unwrap().mcp_servers.is_empty());
    }

    #[test]
    fn rejects_bad_documents() {
        assert!(err("").contains("empty"));
        assert!(err("{ nope").contains("invalid JSON"));
        assert!(err(r#"{"mcpServers": []}"#).contains("invalid config"));
    }

    #[test]
    fn rejects_bad_names() {
        for name in ["a__b", "_a", "a_", "a b", ""] {
            let text = format!(r#"{{"mcpServers": {{"{name}": {{"command": "x"}}}}}}"#);
            assert!(err(&text).contains("name must be"), "{name:?}");
        }
    }

    #[test]
    fn rejects_bad_transports() {
        let cases = [
            (r#"{}"#, "either 'command'"),
            (r#"{"command":"x","url":"http://h"}"#, "not both"),
            (r#"{"type":"sse","url":"http://h"}"#, "unsupported type"),
            (r#"{"type":"http","command":"x"}"#, "does not match"),
            (r#"{"command":"x","headers":{"a":"b"}}"#, "only to http"),
            (r#"{"url":"http://h","env":{"a":"b"}}"#, "only to stdio"),
        ];
        for (server, expected) in cases {
            let text = format!(r#"{{"mcpServers": {{"s": {server}}}}}"#);
            assert!(err(&text).contains(expected), "{server}: {}", err(&text));
        }
    }

    #[test]
    fn rejects_references_in_command_and_unused_fields() {
        let in_command = r#"{"mcpServers":{"s":{"command":"${keychain:x}"}}}"#;
        assert!(err(in_command).contains("'command' must not"));
        let in_extra = r#"{"mcpServers":{"s":{"command":"x","cwd":"${keychain:x}"}}}"#;
        assert!(err(in_extra).contains("not supported in field \"cwd\""));
    }

    #[test]
    fn errors_do_not_echo_config_text() {
        let text = r#"{"mcpServers":{"s":{"command":"x","env":{"A":"ghp_LEAK ${keychain:x"}}}}"#;
        assert!(!err(text).contains("ghp_LEAK"));
    }

    #[test]
    fn rejects_bad_references_at_load_time() {
        let text = r#"{"mcpServers":{"s":{"command":"x","env":{"A":"${HOME}"}}}}"#;
        assert!(err(text).contains("only '${keychain:<account>}' is supported"));
    }

    #[test]
    fn load_reports_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let message = Config::load(&dir.path().join("nope.json"))
            .unwrap_err()
            .to_string();
        assert!(message.contains("cannot read"));
    }
}
