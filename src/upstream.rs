//! One upstream MCP server, connected lazily and reconnected on demand.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use http::{HeaderName, HeaderValue};
use rmcp::ServiceExt;
use rmcp::handler::client::ClientHandler;
use rmcp::model::{ClientConfig, Implementation, ProtocolVersion, Tool};
use rmcp::service::{NotificationContext, Peer, RoleClient, RoleServer, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStderr;
use tokio::sync::Mutex;

use crate::interpolate::{self, InterpolateError};
use crate::names;
use crate::store::CredentialStore;

pub type RunningClient = RunningService<RoleClient, UpstreamHandler>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How long a failed upstream is left alone before the next connection attempt.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// Upper bound for spawning a server and completing the MCP handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a `list` request may take before the upstream is skipped.
const LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// Prints a diagnostic to stderr. Stdout belongs to the MCP protocol.
pub fn log(message: impl AsRef<str>) {
    eprintln!("toolward: {}", message.as_ref());
}

/// Opens a connection to an upstream. Errors are plain strings and must never
/// contain secret values.
pub trait Connect: Send + Sync {
    fn connect(&self, handler: UpstreamHandler) -> BoxFuture<'_, Result<RunningClient, String>>;
}

/// The connection to the agent, shared by every upstream so that a change on
/// an upstream can be passed on.
#[derive(Default)]
pub struct Hub {
    downstream: StdMutex<Option<Peer<RoleServer>>>,
}

impl Hub {
    pub fn set_downstream(&self, peer: Peer<RoleServer>) {
        *self.downstream.lock().unwrap() = Some(peer);
    }

    pub fn downstream(&self) -> Option<Peer<RoleServer>> {
        self.downstream.lock().unwrap().clone()
    }
}

/// How the agent-facing names of one upstream's tools map back.
#[derive(Default, Clone)]
struct ToolMap {
    exposed: HashMap<String, String>,
    originals: HashSet<String>,
}

struct Shared {
    /// Secret values substituted into the connection, for redaction.
    secrets: StdMutex<Vec<String>>,
    hub: OnceLock<Arc<Hub>>,
    tools: StdMutex<Option<ToolMap>>,
}

impl Shared {
    fn forget_tools(&self) {
        *self.tools.lock().unwrap() = None;
    }

    fn downstream(&self) -> Option<Peer<RoleServer>> {
        self.hub.get().and_then(|hub| hub.downstream())
    }
}

/// Receives notifications from one upstream.
#[derive(Clone)]
pub struct UpstreamHandler {
    shared: Arc<Shared>,
}

impl UpstreamHandler {
    /// Connectors report the secrets they used so that later errors, which
    /// the server may have filled with echoed headers, can be masked.
    pub fn remember_secrets(&self, secrets: &[String]) {
        *self.shared.secrets.lock().unwrap() = secrets.to_vec();
    }
}

impl ClientHandler for UpstreamHandler {
    /// Offers the newest version that still has the `initialize` handshake.
    /// rmcp's default, 2026-07-28, has none, and servers such as GitHub's then
    /// answer `initialize` but reject the follow-up with "invalid session".
    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::default();
        info.protocol_version = ProtocolVersion::LATEST_WITH_INITIALIZE;
        info.client_info = Implementation::new("toolward", env!("CARGO_PKG_VERSION"));
        info
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.shared.forget_tools();
        if let Some(peer) = self.shared.downstream() {
            let _ = peer.notify_tool_list_changed().await;
        }
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        if let Some(peer) = self.shared.downstream() {
            let _ = peer.notify_resource_list_changed().await;
        }
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        if let Some(peer) = self.shared.downstream() {
            let _ = peer.notify_prompt_list_changed().await;
        }
    }
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
    fn connect(&self, handler: UpstreamHandler) -> BoxFuture<'_, Result<RunningClient, String>> {
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
            handler.remember_secrets(&built.secrets);
            let (transport, stderr) = TokioChildProcess::builder(built.command)
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|err| format!("cannot start {:?}: {err}", self.spec.command))?;
            if let Some(stderr) = stderr {
                forward_stderr(self.name.clone(), stderr, built.secrets.clone());
            }
            // The upstream controls this error text and may echo its env back.
            handler
                .serve(transport)
                .await
                .map_err(|err| redact(&format!("handshake failed: {err}"), &built.secrets))
        })
    }
}

/// A streamable HTTP server.
pub struct HttpSpec {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// Connects to a URL, expanding `${keychain:...}` references in the headers
/// just before the request is made.
pub struct HttpConnector {
    spec: HttpSpec,
    store: Arc<dyn CredentialStore>,
}

impl HttpConnector {
    pub fn new(spec: HttpSpec, store: Arc<dyn CredentialStore>) -> Self {
        Self { spec, store }
    }
}

/// Headers with their secrets resolved, and those secrets for redaction.
/// Blocking: the store may show an OS prompt. Error text never contains a
/// header value.
pub fn build_headers(
    headers: &[(String, String)],
    store: &dyn CredentialStore,
) -> Result<(HashMap<HeaderName, HeaderValue>, Vec<String>), String> {
    let mut secrets = Vec::new();
    let mut out = HashMap::new();
    for (key, value) in headers {
        let name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|_| format!("invalid header name {key:?}"))?;
        let expanded = interpolate::expand_collecting(value, store, &mut secrets)
            .map_err(|err| err.to_string())?;
        let mut value = HeaderValue::from_str(&expanded)
            .map_err(|_| format!("invalid value for header {key:?}"))?;
        value.set_sensitive(true);
        if out.insert(name, value).is_some() {
            return Err(format!("header {key:?} is set twice (names ignore case)"));
        }
    }
    Ok((out, secrets))
}

impl Connect for HttpConnector {
    fn connect(&self, handler: UpstreamHandler) -> BoxFuture<'_, Result<RunningClient, String>> {
        Box::pin(async move {
            let headers = self.spec.headers.clone();
            let store = Arc::clone(&self.store);
            let (headers, secrets) =
                tokio::task::spawn_blocking(move || build_headers(&headers, store.as_ref()))
                    .await
                    .map_err(|err| err.to_string())??;
            handler.remember_secrets(&secrets);
            let config = StreamableHttpClientTransportConfig::with_uri(self.spec.url.as_str())
                .custom_headers(headers);
            let transport = StreamableHttpClientTransport::from_config(config);
            // The server controls this error text and may echo headers back.
            handler
                .serve(transport)
                .await
                .map_err(|err| redact(&format!("handshake failed: {err}"), &secrets))
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
    shared: Arc<Shared>,
    list_timeout: Duration,
}

impl Upstream {
    pub fn new(name: impl Into<String>, connector: Box<dyn Connect>) -> Self {
        Self {
            name: name.into(),
            connector,
            state: Mutex::new(State::Idle),
            list_timeout: LIST_TIMEOUT,
            shared: Arc::new(Shared {
                secrets: StdMutex::new(Vec::new()),
                hub: OnceLock::new(),
                tools: StdMutex::new(None),
            }),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Replaces the time a `list` request may take. Tests use a short one.
    pub fn with_list_timeout(mut self, timeout: Duration) -> Self {
        self.list_timeout = timeout;
        self
    }

    /// Runs a `list` request, giving up after the list timeout. Errors are
    /// redacted, so they are safe to show.
    pub async fn bounded<T, E: std::fmt::Display>(
        &self,
        request: impl Future<Output = Result<T, E>>,
    ) -> Result<T, String> {
        match tokio::time::timeout(self.list_timeout, request).await {
            Ok(result) => result.map_err(|err| self.redact(&err.to_string())),
            Err(_) => Err(format!(
                "no response to a list request within {}s",
                self.list_timeout.as_secs_f32()
            )),
        }
    }

    /// Masks the secrets of this upstream in `text`.
    pub fn redact(&self, text: &str) -> String {
        redact(text, &self.shared.secrets.lock().unwrap())
    }

    /// Lets notifications from this upstream reach the agent.
    pub fn attach(&self, hub: Arc<Hub>) {
        let _ = self.shared.hub.set(hub);
    }

    /// Lists the tools under the names the agent sees (without the
    /// `<server>__` prefix) and remembers how to map them back.
    pub async fn tools(&self) -> Result<Vec<Tool>, String> {
        let peer = self.peer().await?;
        let mut tools = self.bounded(peer.list_all_tools()).await?;
        let originals: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        let assignment = names::assign(&self.name, &originals);
        let by_original: HashMap<&str, &str> = assignment
            .names
            .iter()
            .map(|(exposed, original)| (original.as_str(), exposed.as_str()))
            .collect();
        let mut map = ToolMap::default();
        let mut renamed = Vec::new();
        tools.retain_mut(|tool| {
            let original = tool.name.to_string();
            let Some(&exposed) = by_original.get(original.as_str()) else {
                return false;
            };
            // The upstream listed the same name twice: keep the first.
            if map.originals.contains(&original) {
                return false;
            }
            if exposed != original {
                renamed.push((original.clone(), exposed.to_owned()));
            }
            map.exposed.insert(exposed.to_owned(), original.clone());
            map.originals.insert(original);
            tool.name = exposed.to_owned().into();
            true
        });
        let mut slot = self.shared.tools.lock().unwrap();
        let changed = slot.as_ref().is_none_or(|old| old.exposed != map.exposed);
        *slot = Some(map);
        drop(slot);
        if changed {
            for (original, exposed) in renamed {
                log(format!(
                    "tool {original:?} of {:?} is exposed as {:?}",
                    self.name,
                    format!("{}{}{exposed}", self.name, names::SEPARATOR)
                ));
            }
            for original in &assignment.dropped {
                log(format!(
                    "tool {original:?} of {:?} is dropped: its name collides with another tool",
                    self.name
                ));
            }
        }
        Ok(tools)
    }

    /// `(exposed, original)` pairs from the last listing, sorted.
    pub fn tool_names(&self) -> Vec<(String, String)> {
        let slot = self.shared.tools.lock().unwrap();
        let mut pairs: Vec<(String, String)> = slot
            .iter()
            .flat_map(|map| map.exposed.iter())
            .map(|(exposed, original)| (exposed.clone(), original.clone()))
            .collect();
        pairs.sort();
        pairs
    }

    /// The upstream's own name for a tool the agent called. Accepts the
    /// exposed name and the original one. Lists the tools again when unknown.
    pub async fn original_tool(&self, called: &str) -> Result<Option<String>, String> {
        for attempt in 0..2 {
            if let Some(map) = self.shared.tools.lock().unwrap().as_ref() {
                if let Some(original) = map.exposed.get(called) {
                    return Ok(Some(original.clone()));
                }
                if map.originals.contains(called) {
                    return Ok(Some(called.to_owned()));
                }
            }
            if attempt == 0 {
                self.tools().await?;
            }
        }
        Ok(None)
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
        let connected = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.connector.connect(UpstreamHandler {
                shared: Arc::clone(&self.shared),
            }),
        )
        .await
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
