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

    /// Adds secrets that appeared after the connection was made, such as a
    /// token the connector refreshed.
    pub fn add_secrets(&self, secrets: &[String]) {
        let mut known = self.shared.secrets.lock().unwrap();
        for secret in secrets {
            if !known.contains(secret) {
                known.push(secret.clone());
            }
        }
    }
}

impl ClientHandler for UpstreamHandler {
    /// Offers the newest version that still has the `initialize` handshake.
    /// rmcp's default, 2026-07-28, has none, and servers such as GitHub's then
    /// answer `initialize` but reject the follow-up with "invalid session".
    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::default();
        info.protocol_version = ProtocolVersion::LATEST_WITH_INITIALIZE;
        info.client_info = Implementation::new("toolward", env!("GIT_VERSION"));
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
    let patterns: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    mask_text(text, &patterns).unwrap_or_else(|| text.to_owned())
}

/// Replaces every match of every pattern with `[REDACTED]`, or returns `None`
/// when nothing matches. Matches that overlap or touch become one mask, so no
/// part of a secret that overlaps another one is left behind.
fn mask_text<P: AsRef<str>>(text: &str, patterns: &[P]) -> Option<String> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for pattern in patterns {
        let pattern = pattern.as_ref();
        if !pattern.is_empty() {
            spans.extend(
                text.match_indices(pattern)
                    .map(|(start, found)| (start, start + found.len())),
            );
        }
    }
    if spans.is_empty() {
        return None;
    }
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut spans = spans.into_iter().peekable();
    while let Some((start, mut end)) = spans.next() {
        while let Some(&(next_start, next_end)) = spans.peek() {
            if next_start > end {
                break;
            }
            end = end.max(next_end);
            spans.next();
        }
        out.push_str(&text[copied..start]);
        out.push_str("[REDACTED]");
        copied = end;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// Secrets shorter than this are not masked in results: they would match
/// ordinary text, and a value that short is no secret worth hiding.
const MIN_RESULT_SECRET_LEN: usize = 4;

/// Every form in which a secret may appear inside a JSON string value: as is,
/// JSON-escaped (when the text is itself JSON) and percent-encoded (in URLs).
/// Longest first, so a secret that contains another one is fully masked.
fn result_patterns(secrets: &[String]) -> Vec<String> {
    let mut whole: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|s| s.len() >= MIN_RESULT_SECRET_LEN)
        .collect();
    // A multi-line secret (PEM key, JSON key file) may come back one line at a
    // time, so every line of it counts as a secret too.
    let lines: Vec<&str> = whole
        .iter()
        .flat_map(|s| s.lines().map(str::trim))
        .filter(|line| line.len() >= MIN_LINE_SECRET_LEN)
        .collect();
    whole.extend(lines);

    let mut patterns = Vec::new();
    for secret in whole {
        patterns.push(secret.to_owned());
        let json = serde_json::to_string(secret).unwrap_or_default();
        if let Some(inner) = json.strip_prefix('"').and_then(|j| j.strip_suffix('"')) {
            patterns.push(inner.to_owned());
            // Some encoders (PHP) also escape the slash.
            patterns.push(inner.replace('/', "\\/"));
            // JSON inside a JSON string (a tool that returns a JSON document).
            let twice = serde_json::to_string(inner).unwrap_or_default();
            if let Some(inner) = twice.strip_prefix('"').and_then(|j| j.strip_suffix('"')) {
                patterns.push(inner.to_owned());
            }
        }
        for hex in [true, false] {
            let mut encoded = String::new();
            for byte in secret.bytes() {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                    encoded.push(byte as char);
                } else if hex {
                    encoded.push_str(&format!("%{byte:02X}"));
                } else {
                    encoded.push_str(&format!("%{byte:02x}"));
                }
            }
            patterns.push(encoded);
        }
        patterns.extend(base64_forms(secret.as_bytes()));
    }
    patterns.retain(|p| p.len() >= MIN_RESULT_SECRET_LEN);
    patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
    patterns.dedup();
    patterns
}

/// A line of a multi-line secret must be at least this long to be masked alone.
const MIN_LINE_SECRET_LEN: usize = 8;

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(BASE64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// The text a secret becomes inside base64 data, whatever its alignment. Only
/// the characters that depend on the secret alone are kept.
fn base64_forms(secret: &[u8]) -> Vec<String> {
    let mut forms = Vec::new();
    for offset in 0..3usize {
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(secret);
        let encoded = base64_encode(&padded);
        let start = [0, 2, 3][offset];
        let tail = usize::from(!(offset + secret.len()).is_multiple_of(3));
        let end = encoded.len();
        if end > start + tail {
            forms.push(encoded[start..end - tail].to_owned());
        }
    }
    forms
}

/// Keys of the MCP protocol itself. Inside a protocol position their names are
/// never masked, so a secret that is an ordinary word cannot rename a field.
const PROTOCOL_KEYS: &[&str] = &[
    "type",
    "text",
    "data",
    "blob",
    "mimeType",
    "uri",
    "name",
    "title",
    "description",
    "role",
    "content",
    "contents",
    "resource",
    "annotations",
    "audience",
    "icons",
    "theme",
    "_meta",
    "structuredContent",
    "isError",
    "resultType",
    "inputSchema",
    "outputSchema",
    "arguments",
    "messages",
    "tools",
    "resources",
    "prompts",
    "nextCursor",
    "code",
    "message",
];

/// Keys through which the result stays a protocol position. Anything else
/// (`structuredContent`, `_meta`, error `data`, schemas, call arguments) holds
/// free-form data written by the upstream, and is masked without exceptions.
const PROTOCOL_DESCEND: &[&str] = &[
    "tools",
    "resources",
    "prompts",
    "content",
    "contents",
    "messages",
    "resource",
    "annotations",
    "icons",
];

/// Whether `text` under `key` is a protocol word or identifier the agent must
/// send back or the client must parse unchanged. Masking it would break the
/// next call, so a value of the right shape is left alone.
fn is_protocol_value(key: &str, text: &str) -> bool {
    let word = |extra: &[char]| {
        !text.is_empty()
            && text.len() <= 128
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || extra.contains(&c))
    };
    match key {
        "type" | "role" | "resultType" | "theme" | "audience" => word(&[]),
        "name" => word(&['.', ':', '/']),
        "mimeType" => word(&['.', '+', '/']) && text.matches('/').count() == 1,
        _ => false,
    }
}

/// Masks the patterns in every string of `value`. `protocol` is true while
/// `value` is at a position of the MCP protocol. Returns whether anything changed.
fn mask_strings<P: AsRef<str>>(
    value: &mut serde_json::Value,
    patterns: &[P],
    protocol: bool,
) -> bool {
    let mut changed = false;
    match value {
        serde_json::Value::String(text) => {
            if let Some(masked) = mask_text(text, patterns) {
                *text = masked;
                changed = true;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                changed |= mask_strings(item, patterns, protocol);
            }
        }
        serde_json::Value::Object(map) => {
            let entries = std::mem::take(map);
            for (mut key, mut item) in entries {
                if !(protocol && PROTOCOL_KEYS.contains(&key.as_str()))
                    && let Some(masked) = mask_text(&key, patterns)
                {
                    key = masked;
                    changed = true;
                }
                let child = protocol
                    && (PROTOCOL_DESCEND.contains(&key.as_str())
                        || (key == "arguments" && item.is_array()));
                let keep = protocol && exempt_value(&key, &item);
                if !keep {
                    changed |= mask_strings(&mut item, patterns, child);
                }
                map.insert(key, item);
            }
        }
        _ => {}
    }
    changed
}

/// A protocol value (or a list of them, such as `audience`) to leave as it is.
fn exempt_value(key: &str, item: &serde_json::Value) -> bool {
    match item {
        serde_json::Value::String(text) => is_protocol_value(key, text),
        serde_json::Value::Array(items) => {
            key == "audience"
                && items
                    .iter()
                    .all(|i| i.as_str().is_some_and(|t| is_protocol_value(key, t)))
        }
        _ => false,
    }
}

/// Masks `secrets` in every string of `value` (text, structured content,
/// resource and prompt bodies). A value that cannot be inspected is an error,
/// never passed on unchecked.
pub fn redact_value<T>(value: T, secrets: &[String]) -> Result<T, String>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let patterns = result_patterns(secrets);
    if patterns.is_empty() {
        return Ok(value);
    }
    let mut json = serde_json::to_value(&value)
        .map_err(|_| "cannot inspect the upstream result for secrets".to_owned())?;
    // Untouched values go through as they came: a round trip through JSON
    // can reorder keys.
    if !mask_strings(&mut json, &patterns, true) {
        return Ok(value);
    }
    serde_json::from_value(json)
        .map_err(|_| "cannot inspect the upstream result for secrets".to_owned())
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

    /// Masks the secrets of this upstream in a result on its way to the agent.
    pub fn redact_result<T>(&self, value: T) -> Result<T, String>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let secrets = self.shared.secrets.lock().unwrap().clone();
        redact_value(value, &secrets)
    }

    /// Lets notifications from this upstream reach the agent.
    pub fn attach(&self, hub: Arc<Hub>) {
        let _ = self.shared.hub.set(hub);
    }

    /// Lists the tools under the names the agent sees (without the
    /// `<server>__` prefix) and remembers how to map them back.
    pub async fn tools(&self) -> Result<Vec<Tool>, String> {
        let peer = self.list_peer().await?;
        self.tools_from(&peer).await
    }

    async fn tools_from(&self, peer: &Peer<RoleClient>) -> Result<Vec<Tool>, String> {
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
                // A tool call may wait for a slow start as long as any other
                // call; only a plain listing gives up early.
                let peer = self.peer().await?;
                self.tools_from(&peer).await?;
            }
        }
        Ok(None)
    }

    /// Like [`Upstream::peer`], for a `list` request: connecting may take no
    /// longer than the list timeout, so one hung upstream cannot hold up the
    /// whole listing. A connection that times out counts as a failure and is
    /// not tried again for [`RETRY_AFTER`].
    pub async fn list_peer(&self) -> Result<Peer<RoleClient>, String> {
        match tokio::time::timeout(self.list_timeout, self.peer()).await {
            Ok(result) => result,
            Err(_) => {
                let reason = format!("no connection within {}s", self.list_timeout.as_secs_f32());
                // Another request that is still connecting holds the lock;
                // it will record its own outcome.
                if let Ok(mut state) = self.state.try_lock()
                    && match &*state {
                        State::Idle => true,
                        State::Failed { at, .. } => at.elapsed() >= RETRY_AFTER,
                        // A connection that died on its own, then hung on reconnect.
                        State::Running(client) => {
                            client.is_closed() || client.peer().is_transport_closed()
                        }
                        State::Closed => false,
                    }
                {
                    *state = State::Failed {
                        at: Instant::now(),
                        reason: reason.clone(),
                    };
                }
                Err(reason)
            }
        }
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
    fn results_are_masked_in_keys_base64_lowercase_percent_and_lines() {
        use serde_json::json;
        let secret = "tok/en+value=x".to_owned();
        let pem = "-----BEGIN KEY-----\nAAAABBBBCCCCDDDD\n-----END KEY-----".to_owned();
        let secrets = vec![secret.clone(), pem];
        // The secret at every base64 alignment.
        let b64 = |prefix: &str| base64_encode(format!("{prefix}{secret}").as_bytes());
        let value = json!({
            "tok/en+value=x": "key",
            "lower": "tok%2fen%2bvalue%3dx",
            "slash": "tok\\/en+value=x",
            "line": "found AAAABBBBCCCCDDDD here",
            "b0": b64(""),
            "b1": b64("a"),
            "b2": b64("ab"),
        });
        let out = redact_value(value, &secrets).unwrap();
        let text = out.to_string();
        assert!(!text.contains("tok/en"), "{text}");
        assert!(!text.contains("AAAABBBB"), "{text}");
        for key in ["b0", "b1", "b2"] {
            assert!(
                out[key].as_str().unwrap().contains("[REDACTED]"),
                "{key}: {text}"
            );
        }
    }

    #[test]
    fn results_are_masked_in_every_encoding_and_every_field() {
        use serde_json::json;
        let secrets = vec!["s3\"cr/et".to_owned(), "abc".to_owned()];
        let value = json!({
            "a": "plain s3\"cr/et end",
            "b": ["{\"k\": \"s3\\\"cr/et\"}", "q=s3%22cr%2Fet", "abc stays"],
            "s3\"cr/et": 1,
        });
        let out = redact_value(value, &secrets).unwrap();
        assert_eq!(out["a"], "plain [REDACTED] end");
        assert_eq!(out["b"][0], "{\"k\": \"[REDACTED]\"}");
        assert_eq!(out["b"][1], "q=[REDACTED]");
        // Too short to mask without hitting ordinary text.
        assert_eq!(out["b"][2], "abc stays");
    }

    struct Hang;

    impl Connect for Hang {
        fn connect(
            &self,
            _handler: UpstreamHandler,
        ) -> BoxFuture<'_, Result<RunningClient, String>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn a_hung_connection_ends_a_listing_and_is_not_retried_at_once() {
        let upstream =
            Upstream::new("hang", Box::new(Hang)).with_list_timeout(Duration::from_millis(100));
        let started = Instant::now();
        let err = upstream.list_peer().await.unwrap_err();
        assert!(err.contains("no connection"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
        // The failure is remembered: the next request answers at once.
        let started = Instant::now();
        let again = upstream.list_peer().await.unwrap_err();
        assert_eq!(again, err);
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn overlapping_secrets_leave_no_fragment() {
        let secrets = vec!["abcdef".to_owned(), "defghi".to_owned()];
        assert_eq!(redact("x abcdefghi y", &secrets), "x [REDACTED] y");
        let out = redact_value(serde_json::json!(["abcdefghi"]), &secrets).unwrap();
        assert_eq!(out[0], "[REDACTED]");
    }

    #[test]
    fn a_secret_that_is_a_common_word_cannot_break_the_protocol() {
        use serde_json::json;
        let secrets = vec!["text".to_owned()];
        let value = json!({"type": "text", "text": "a text", "mimeType": "text/plain",
                           "text/odd": 1});
        let out = redact_value(value, &secrets).unwrap();
        assert_eq!(out["type"], "text");
        assert_eq!(out["mimeType"], "text/plain");
        assert_eq!(out["text"], "a [REDACTED]");
        assert_eq!(out["[REDACTED]/odd"], 1);
    }

    #[test]
    fn free_form_data_is_masked_even_under_protocol_names() {
        use serde_json::json;
        let secrets = vec!["ghp_abcdef".to_owned()];
        let value = json!({
            "content": [{"type": "text", "text": "x"}],
            "structuredContent": {"credentials": [
                {"name": "ghp_abcdef", "type": "Bearer ghp_abcdef", "mimeType": "a/b; t=ghp_abcdef"}]},
            "_meta": {"name": "ghp_abcdef"},
        });
        let out = redact_value(value, &secrets).unwrap().to_string();
        assert!(!out.contains("ghp_abcdef"), "{out}");
    }

    #[test]
    fn enum_values_survive_a_word_secret() {
        let secrets = vec!["user".to_owned(), "dark".to_owned()];
        let value = serde_json::json!({"content": [{"type": "text", "text": "hi user",
            "annotations": {"audience": ["user", "assistant"]}}]});
        let out = redact_value(value, &secrets).unwrap();
        assert_eq!(out["content"][0]["annotations"]["audience"][0], "user");
        assert_eq!(out["content"][0]["text"], "hi [REDACTED]");
    }

    #[test]
    fn overlapping_multibyte_secrets_do_not_panic() {
        let secrets = vec!["日本語パス".to_owned(), "語パスワード".to_owned()];
        assert_eq!(redact("a日本語パスワードb", &secrets), "a[REDACTED]b");
    }

    #[test]
    fn json_inside_json_is_masked() {
        let secrets = vec!["pa\"ss".to_owned()];
        let inner = serde_json::json!({"k": "pa\"ss"}).to_string();
        let outer = serde_json::json!({"doc": inner}).to_string();
        let value = serde_json::json!({"deep": outer});
        let out = redact_value(value, &secrets).unwrap().to_string();
        assert!(
            !out.contains("pa\\\\\\\"ss") && !out.contains("pa"),
            "{out}"
        );
    }

    #[test]
    fn untouched_values_keep_their_key_order() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"z": 1, "a": 2, "m": "plain"}"#).unwrap();
        let out = redact_value(value.clone(), &["secret-value".to_owned()]).unwrap();
        assert_eq!(out, value);
    }

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
