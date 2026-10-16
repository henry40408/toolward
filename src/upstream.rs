//! One upstream MCP server, connected lazily and reconnected on demand.

use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::ServiceExt;
use rmcp::service::{Peer, RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStderr;
use tokio::sync::Mutex;

use crate::interpolate::{self, InterpolateError};
use crate::store::CredentialStore;

pub type RunningClient = RunningService<RoleClient, ()>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How long a failed upstream is left alone before the next connection attempt.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// Upper bound for spawning a server and completing the MCP handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Prints a diagnostic to stderr. Stdout belongs to the MCP protocol.
pub fn log(message: impl AsRef<str>) {
    eprintln!("toolward: {}", message.as_ref());
}

/// Opens a connection to an upstream. Errors are plain strings and must never
/// contain secret values.
pub trait Connect: Send + Sync {
    fn connect(&self) -> BoxFuture<'_, Result<RunningClient, String>>;
}

/// A stdio server started as a child process.
pub struct StdioSpec {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Spawns a child process, expanding `${keychain:...}` references just before it starts.
pub struct StdioConnector {
    name: String,
    spec: StdioSpec,
    store: Arc<dyn CredentialStore>,
}

impl StdioConnector {
    pub fn new(name: impl Into<String>, spec: StdioSpec, store: Arc<dyn CredentialStore>) -> Self {
        Self {
            name: name.into(),
            spec,
            store,
        }
    }
}

/// A child command with its secrets resolved.
pub struct BuiltCommand {
    pub command: tokio::process::Command,
    /// Every secret value substituted into the command, for redaction.
    pub secrets: Vec<String>,
}

/// Builds the child command with secrets resolved. Blocking: the store may
/// show an OS prompt.
pub fn build_command(
    spec: &StdioSpec,
    store: &dyn CredentialStore,
) -> Result<BuiltCommand, InterpolateError> {
    let mut secrets = Vec::new();
    let mut command = tokio::process::Command::new(&spec.command);
    for arg in &spec.args {
        command.arg(interpolate::expand_collecting(arg, store, &mut secrets)?);
    }
    for (key, value) in &spec.env {
        command.env(
            key,
            interpolate::expand_collecting(value, store, &mut secrets)?,
        );
    }
    command.kill_on_drop(true);
    Ok(BuiltCommand { command, secrets })
}

/// Replaces every secret value in `text` with `[REDACTED]`.
pub fn redact(text: &str, secrets: &[String]) -> String {
    let mut ordered: Vec<&String> = secrets.iter().filter(|s| !s.is_empty()).collect();
    // Longest first, so a secret that contains another one is fully masked.
    ordered.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = text.to_owned();
    for secret in ordered {
        out = out.replace(secret.as_str(), "[REDACTED]");
    }
    out
}

/// Relays a child's stderr to ours with secrets masked. Stderr is piped rather
/// than inherited because agents keep MCP stderr in logs they can read.
fn forward_stderr(name: String, stderr: ChildStderr, secrets: Vec<String>) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let text = String::from_utf8_lossy(&line);
                    eprintln!("[{name}] {}", redact(text.trim_end(), &secrets));
                }
            }
        }
    });
}

impl Connect for StdioConnector {
    fn connect(&self) -> BoxFuture<'_, Result<RunningClient, String>> {
        Box::pin(async move {
            let spec = StdioSpec {
                command: self.spec.command.clone(),
                args: self.spec.args.clone(),
                env: self.spec.env.clone(),
            };
            let store = Arc::clone(&self.store);
            let built = tokio::task::spawn_blocking(move || build_command(&spec, store.as_ref()))
                .await
                .map_err(|err| err.to_string())?
                .map_err(|err| err.to_string())?;
            let (transport, stderr) = TokioChildProcess::builder(built.command)
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|err| format!("cannot start {:?}: {err}", self.spec.command))?;
            if let Some(stderr) = stderr {
                forward_stderr(self.name.clone(), stderr, built.secrets.clone());
            }
            // The upstream controls this error text and may echo its env back.
            ().serve(transport)
                .await
                .map_err(|err| redact(&format!("handshake failed: {err}"), &built.secrets))
        })
    }
}

enum State {
    Idle,
    Running(RunningClient),
    Failed {
        at: Instant,
        reason: String,
    },
    /// After `shutdown()`: no new child may be started.
    Closed,
}

pub struct Upstream {
    name: String,
    connector: Box<dyn Connect>,
    state: Mutex<State>,
}

impl Upstream {
    pub fn new(name: impl Into<String>, connector: Box<dyn Connect>) -> Self {
        Self {
            name: name.into(),
            connector,
            state: Mutex::new(State::Idle),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a handle to the live connection, connecting first when needed.
    /// A failure is remembered for [`RETRY_AFTER`] so a broken upstream does
    /// not slow down every request.
    pub async fn peer(&self) -> Result<Peer<RoleClient>, String> {
        let mut state = self.state.lock().await;
        match &*state {
            // `is_closed()` alone misses a child that exited on its own.
            State::Running(client)
                if !client.is_closed() && !client.peer().is_transport_closed() =>
            {
                return Ok(client.peer().clone());
            }
            State::Failed { at, reason } if at.elapsed() < RETRY_AFTER => {
                return Err(reason.clone());
            }
            State::Closed => return Err("proxy is shutting down".to_owned()),
            _ => {}
        }
        let connected = match tokio::time::timeout(CONNECT_TIMEOUT, self.connector.connect()).await
        {
            Ok(result) => result,
            Err(_) => Err(format!("no response within {}s", CONNECT_TIMEOUT.as_secs())),
        };
        match connected {
            Ok(client) => {
                let peer = client.peer().clone();
                *state = State::Running(client);
                Ok(peer)
            }
            Err(reason) => {
                *state = State::Failed {
                    at: Instant::now(),
                    reason: reason.clone(),
                };
                Err(reason)
            }
        }
    }

    pub async fn shutdown(&self) {
        let previous = std::mem::replace(&mut *self.state.lock().await, State::Closed);
        if let State::Running(client) = previous {
            let _ = client.cancel().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    #[test]
    fn redact_masks_every_secret_longest_first() {
        let secrets = vec!["abc".to_owned(), "abcdef".to_owned(), String::new()];
        assert_eq!(
            redact("token=abcdef and abc!", &secrets),
            "token=[REDACTED] and [REDACTED]!"
        );
        assert_eq!(redact("nothing here", &secrets), "nothing here");
    }

    #[test]
    fn build_command_collects_the_secrets_it_substitutes() {
        let store = MemoryStore::with(&[("tok", "s3cr3t")]);
        let spec = StdioSpec {
            command: "x".into(),
            args: vec!["--flag".into()],
            env: vec![
                ("A".into(), "Bearer ${keychain:tok}".into()),
                ("B".into(), "plain".into()),
            ],
        };
        let built = build_command(&spec, &store).unwrap();
        assert_eq!(built.secrets, ["s3cr3t"]);
        let envs: Vec<(String, Option<String>)> = built
            .command
            .as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(envs.contains(&("A".into(), Some("Bearer s3cr3t".into()))));
        assert!(envs.contains(&("B".into(), Some("plain".into()))));
    }

    #[test]
    fn build_command_fails_on_a_missing_secret() {
        let spec = StdioSpec {
            command: "x".into(),
            args: vec![],
            env: vec![("A".into(), "${keychain:nope}".into())],
        };
        let err = build_command(&spec, &MemoryStore::new()).err().unwrap();
        assert!(err.to_string().contains("nope"));
    }
}
