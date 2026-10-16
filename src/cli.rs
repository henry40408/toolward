use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::config::{self, Config};
use crate::store::{CredentialStore, validate_account};

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Config file [default: ~/.config/toolward/config.json]
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage secrets in the credential store
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Validate the config and report which referenced secrets are missing
    Check,
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Store a secret, read from a hidden prompt or from stdin
    Set { account: String },
    /// Remove a secret
    Delete { account: String },
}

impl Cli {
    pub fn config_path(&self) -> Result<PathBuf> {
        match &self.config {
            Some(path) => Ok(path.clone()),
            None => Ok(config::default_path()?),
        }
    }
}

pub fn secret_set(
    store: &dyn CredentialStore,
    account: &str,
    secret: &str,
    out: &mut dyn Write,
) -> Result<()> {
    validate_account(account)?;
    if secret.is_empty() {
        bail!("refusing to store an empty secret");
    }
    store.set(account, secret)?;
    writeln!(out, "stored secret for {account:?}")?;
    Ok(())
}

pub fn secret_delete(
    store: &dyn CredentialStore,
    account: &str,
    out: &mut dyn Write,
) -> Result<()> {
    if store.delete(account)? {
        writeln!(out, "deleted secret for {account:?}")?;
    } else {
        writeln!(out, "no secret stored for {account:?}")?;
    }
    Ok(())
}

/// Prints the status of every referenced secret. Never prints a secret value.
/// Returns `true` when all of them are present.
pub fn check(config: &Config, store: &dyn CredentialStore, out: &mut dyn Write) -> Result<bool> {
    let mut all_present = true;
    for (server, accounts) in config.references() {
        writeln!(out, "{server}")?;
        if accounts.is_empty() {
            writeln!(out, "  (no secret references)")?;
        }
        for account in accounts {
            let status = match store.get(&account) {
                Ok(Some(_)) => "ok".to_owned(),
                Ok(None) => "MISSING".to_owned(),
                Err(err) => format!("ERROR ({err})"),
            };
            all_present &= status == "ok";
            writeln!(out, "  {account}: {status}")?;
        }
    }
    Ok(all_present)
}

/// Reads a secret without echoing it when stdin is a terminal; otherwise reads one line.
pub fn read_secret(account: &str) -> Result<String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let first = rpassword::prompt_password(format!("Secret for {account}: "))?;
        let again = rpassword::prompt_password("Repeat to confirm: ")?;
        if first != again {
            bail!("the two entries differ");
        }
        Ok(first)
    } else {
        // Read everything so multi-line secrets (PEM keys, JSON files) stay intact.
        let mut text = String::new();
        stdin
            .lock()
            .read_to_string(&mut text)
            .context("cannot read the secret from stdin")?;
        let secret = text.strip_suffix('\n').unwrap_or(&text);
        Ok(secret.strip_suffix('\r').unwrap_or(secret).to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    const CONFIG: &str = r#"{"mcpServers": {
        "a": {"command": "x", "env": {"T": "${keychain:present}"}},
        "b": {"command": "y", "env": {"T": "${keychain:absent}"}},
        "c": {"command": "z"}
    }}"#;

    #[test]
    fn check_reports_status_without_leaking_values() {
        let store = MemoryStore::with(&[("present", "TOPSECRET")]);
        let mut out = Vec::new();
        let all_present = check(&Config::parse(CONFIG).unwrap(), &store, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!all_present);
        assert!(text.contains("present: ok"));
        assert!(text.contains("absent: MISSING"));
        assert!(text.contains("(no secret references)"));
        assert!(!text.contains("TOPSECRET"));
    }

    #[test]
    fn secret_set_and_delete() {
        let store = MemoryStore::new();
        let mut out = Vec::new();
        secret_set(&store, "gh", "tok", &mut out).unwrap();
        assert_eq!(store.get("gh").unwrap().as_deref(), Some("tok"));
        assert!(!String::from_utf8(out).unwrap().contains("tok\""));
        secret_delete(&store, "gh", &mut Vec::new()).unwrap();
        assert_eq!(store.get("gh").unwrap(), None);
    }

    #[test]
    fn secret_set_rejects_empty_and_bad_account() {
        let store = MemoryStore::new();
        assert!(secret_set(&store, "gh", "", &mut Vec::new()).is_err());
        assert!(secret_set(&store, "a/b", "x", &mut Vec::new()).is_err());
    }
}
