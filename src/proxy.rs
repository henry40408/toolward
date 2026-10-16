//! The MCP server Claude Code talks to. It exposes the tools, resources and
//! prompts of every upstream under the upstream's name and forwards requests.

use std::collections::BTreeMap;
use std::sync::Arc;

use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResponse, ClientRequest,
    GetPromptRequestParams, GetPromptResponse, Implementation, ListPromptsResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams,
    ReadResourceResponse, ResourceContents, ResultType, ServerCapabilities, ServerConfig,
    ServerResult,
};
use rmcp::service::{
    NotificationContext, Peer, PeerRequestOptions, RequestContext, RoleClient, RoleServer,
    ServiceError,
};
use tokio::task::JoinSet;

use crate::config::{Config, Transport};
use crate::names::SEPARATOR;
use crate::oauth::{OAuthConnector, OAuthSpec};
use crate::store::CredentialStore;
use crate::upstream::{HttpConnector, HttpSpec, Hub, StdioConnector, StdioSpec, Upstream, log};

/// Resources are exposed as `toolward://<server>/<percent-encoded upstream URI>`.
const RESOURCE_SCHEME: &str = "toolward://";

#[derive(Clone)]
pub struct Proxy {
    upstreams: Arc<BTreeMap<String, Arc<Upstream>>>,
    hub: Arc<Hub>,
}

impl Proxy {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        let hub = Arc::new(Hub::default());
        let map = upstreams
            .into_iter()
            .map(|upstream| {
                upstream.attach(Arc::clone(&hub));
                (upstream.name().to_owned(), Arc::new(upstream))
            })
            .collect();
        Self {
            upstreams: Arc::new(map),
            hub,
        }
    }

    /// Builds the upstreams described by `config`. Nothing is started yet.
    pub fn from_config(config: &Config, store: &Arc<dyn CredentialStore>) -> Self {
        let mut upstreams = Vec::new();
        for (name, server) in &config.mcp_servers {
            match server.transport() {
                Ok(Transport::Stdio { command, args, env }) => {
                    let spec = StdioSpec {
                        command: command.to_owned(),
                        args: args.to_vec(),
                        env: env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    };
                    let connector = StdioConnector::new(name, spec, Arc::clone(store));
                    upstreams.push(Upstream::new(name, Box::new(connector)));
                }
                Ok(Transport::Http {
                    url,
                    headers,
                    oauth,
                }) => {
                    if let Some(oauth) = oauth {
                        if let Err(reason) = crate::oauth::account_for(name) {
                            log(format!("skipping {name:?}: {reason}"));
                            continue;
                        }
                        let spec = OAuthSpec {
                            server: name.clone(),
                            url: url.to_owned(),
                            client_secret: oauth.client_secret.clone(),
                        };
                        let connector = OAuthConnector::new(spec, Arc::clone(store));
                        upstreams.push(Upstream::new(name, Box::new(connector)));
                        continue;
                    }
                    let spec = HttpSpec {
                        url: url.to_owned(),
                        headers: headers
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    };
                    let connector = HttpConnector::new(spec, Arc::clone(store));
                    upstreams.push(Upstream::new(name, Box::new(connector)));
                }
                Err(reason) => log(format!("skipping {name:?}: {reason}")),
            }
        }
        Self::new(upstreams)
    }

    /// The upstreams, for `toolward check`.
    pub fn upstreams(&self) -> impl Iterator<Item = &Arc<Upstream>> {
        self.upstreams.values()
    }

    pub async fn shutdown(&self) {
        let mut tasks = JoinSet::new();
        for upstream in self.upstreams.values() {
            let upstream = Arc::clone(upstream);
            tasks.spawn(async move { upstream.shutdown().await });
        }
        while tasks.join_next().await.is_some() {}
    }

    fn upstream(&self, server: &str, what: &str) -> Result<&Arc<Upstream>, McpError> {
        self.upstreams
            .get(server)
            .ok_or_else(|| McpError::invalid_params(format!("unknown {what}"), None))
    }
}

/// Errors that did not come from the upstream's own MCP error may contain
/// text the server echoed back, so the upstream's secrets are masked.
fn service_error(upstream: &Upstream, err: ServiceError) -> McpError {
    match err {
        ServiceError::McpError(err) => err,
        other => McpError::internal_error(
            upstream.redact(&format!("upstream request failed: {other}")),
            None,
        ),
    }
}

/// Forwards a tool call and, when the downstream request is cancelled, sends
/// `notifications/cancelled` upstream so a long-running tool stops too.
async fn call_tool_cancellable(
    peer: &Peer<RoleClient>,
    params: CallToolRequestParams,
    cancelled: impl Future<Output = ()>,
) -> Result<CallToolResponse, ServiceError> {
    let mut handle = peer
        .send_cancellable_request(
            ClientRequest::CallToolRequest(CallToolRequest::new(params)),
            PeerRequestOptions::no_options(),
        )
        .await?;
    let outcome = tokio::select! {
        outcome = &mut handle.rx => outcome,
        () = cancelled => {
            let _ = handle.cancel(Some("cancelled by the client".into())).await;
            return Err(ServiceError::Cancelled { reason: None });
        }
    };
    match outcome.map_err(|_| ServiceError::TransportClosed)?? {
        ServerResult::CallToolResult(result) => Ok(CallToolResponse::Complete(result)),
        ServerResult::InputRequiredResult(result) => Ok(CallToolResponse::InputRequired(result)),
        ServerResult::CreateTaskResult(result) => Ok(CallToolResponse::Task(result)),
        _ => Err(ServiceError::UnexpectedResponse),
    }
}

fn unavailable(server: &str, reason: String) -> McpError {
    McpError::internal_error(
        format!("upstream {server:?} is unavailable: {reason}"),
        None,
    )
}

/// Percent-encodes everything but unreserved characters.
fn encode_uri(uri: &str) -> String {
    let mut out = String::with_capacity(uri.len());
    for byte in uri.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn decode_uri(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `toolward://<server>/<encoded>` for an upstream URI.
fn expose_uri(server: &str, uri: &str) -> String {
    format!("{RESOURCE_SCHEME}{server}/{}", encode_uri(uri))
}

/// Splits an exposed URI into the server and the upstream's own URI.
fn restore_uri(uri: &str) -> Option<(&str, String)> {
    let (server, encoded) = uri.strip_prefix(RESOURCE_SCHEME)?.split_once('/')?;
    Some((server, decode_uri(encoded)?))
}

/// Whether the upstream announced the capability. Unknown counts as yes.
fn supports(peer: &rmcp::service::Peer<rmcp::service::RoleClient>, capability: Capability) -> bool {
    let Some(info) = peer.peer_info() else {
        return true;
    };
    match capability {
        Capability::Resources => info.capabilities.resources.is_some(),
        Capability::Prompts => info.capabilities.prompts.is_some(),
    }
}

#[derive(Clone, Copy)]
enum Capability {
    Resources,
    Prompts,
}

impl ServerHandler for Proxy {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_resources_list_changed()
                .enable_prompts()
                .enable_prompts_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new("toolward", env!("CARGO_PKG_VERSION")))
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        self.hub.set_downstream(context.peer);
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tasks = JoinSet::new();
        for upstream in self.upstreams.values() {
            let upstream = Arc::clone(upstream);
            tasks.spawn(async move { (upstream.name().to_owned(), upstream.tools().await) });
        }
        let mut tools = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((name, result)) = joined else { continue };
            match result {
                Ok(list) => tools.extend(list.into_iter().map(|mut tool| {
                    tool.name = format!("{name}{SEPARATOR}{}", tool.name).into();
                    tool
                })),
                // An unavailable upstream is skipped, not fatal.
                Err(reason) => log(format!("skipping upstream {name:?}: {reason}")),
            }
        }
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ListToolsResult {
            tools,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let unknown = || McpError::invalid_params(format!("unknown tool {name:?}"), None);
        let (server, called) = name.split_once(SEPARATOR).ok_or_else(unknown)?;
        let upstream = self.upstreams.get(server).ok_or_else(unknown)?;
        let original = upstream
            .original_tool(called)
            .await
            .map_err(|reason| unavailable(server, reason))?
            .ok_or_else(unknown)?;
        let peer = upstream
            .peer()
            .await
            .map_err(|reason| unavailable(server, reason))?;
        request.name = original.into();
        let response = call_tool_cancellable(&peer, request, context.ct.cancelled())
            .await
            .map_err(|err| service_error(upstream, err))?;
        // Upstreams on older protocol revisions omit `resultType`, which the
        // 2026-07-28 revision spoken to the client requires.
        Ok(match response {
            CallToolResponse::Complete(mut result) => {
                result.result_type.get_or_insert(ResultType::COMPLETE);
                result.into()
            }
            other => other,
        })
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let mut tasks = JoinSet::new();
        for upstream in self.upstreams.values() {
            let upstream = Arc::clone(upstream);
            tasks.spawn(async move {
                let resources = match upstream.peer().await {
                    Ok(peer) if !supports(&peer, Capability::Resources) => Ok(Vec::new()),
                    Ok(peer) => upstream.bounded(peer.list_all_resources()).await,
                    Err(reason) => Err(reason),
                };
                (upstream.name().to_owned(), resources)
            });
        }
        let mut resources = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((name, result)) = joined else { continue };
            match result {
                Ok(list) => resources.extend(list.into_iter().map(|mut resource| {
                    resource.uri = expose_uri(&name, &resource.uri);
                    resource
                })),
                Err(reason) => log(format!("skipping upstream {name:?}: {reason}")),
            }
        }
        resources.sort_by(|a, b| a.uri.cmp(&b.uri));
        Ok(ListResourcesResult {
            resources,
            ..Default::default()
        })
    }

    async fn read_resource(
        &self,
        mut request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        let unknown = || McpError::invalid_params("unknown resource", None);
        let (server, uri) = restore_uri(&request.uri).ok_or_else(unknown)?;
        let server = server.to_owned();
        let upstream = self.upstream(&server, "resource")?;
        let peer = upstream
            .peer()
            .await
            .map_err(|reason| unavailable(&server, reason))?;
        request.uri = uri;
        let mut result = peer
            .read_resource(request)
            .await
            .map_err(|err| service_error(upstream, err))?;
        result.result_type.get_or_insert(ResultType::COMPLETE);
        for content in &mut result.contents {
            match content {
                ResourceContents::TextResourceContents { uri, .. }
                | ResourceContents::BlobResourceContents { uri, .. } => {
                    *uri = expose_uri(&server, uri);
                }
                _ => {}
            }
        }
        Ok(result.into())
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        let mut tasks = JoinSet::new();
        for upstream in self.upstreams.values() {
            let upstream = Arc::clone(upstream);
            tasks.spawn(async move {
                let prompts = match upstream.peer().await {
                    Ok(peer) if !supports(&peer, Capability::Prompts) => Ok(Vec::new()),
                    Ok(peer) => upstream.bounded(peer.list_all_prompts()).await,
                    Err(reason) => Err(reason),
                };
                (upstream.name().to_owned(), prompts)
            });
        }
        let mut prompts = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((name, result)) = joined else { continue };
            match result {
                Ok(list) => prompts.extend(list.into_iter().map(|mut prompt| {
                    prompt.name = format!("{name}{SEPARATOR}{}", prompt.name);
                    prompt
                })),
                Err(reason) => log(format!("skipping upstream {name:?}: {reason}")),
            }
        }
        prompts.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ListPromptsResult {
            prompts,
            ..Default::default()
        })
    }

    async fn get_prompt(
        &self,
        mut request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        let name = request.name.clone();
        let unknown = || McpError::invalid_params(format!("unknown prompt {name:?}"), None);
        let (server, prompt) = name.split_once(SEPARATOR).ok_or_else(unknown)?;
        let upstream = self.upstreams.get(server).ok_or_else(unknown)?;
        let peer = upstream
            .peer()
            .await
            .map_err(|reason| unavailable(server, reason))?;
        request.name = prompt.to_owned();
        let mut result = peer
            .get_prompt(request)
            .await
            .map_err(|err| service_error(upstream, err))?;
        result.result_type.get_or_insert(ResultType::COMPLETE);
        Ok(result.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris_survive_a_round_trip() {
        for uri in [
            "file:///a b/ü.txt?x=1&y=%20#frag",
            "https://example.com/a/b",
            "",
            "x://100%",
        ] {
            let exposed = expose_uri("srv", uri);
            assert!(exposed.starts_with("toolward://srv/"));
            assert!(!exposed["toolward://srv/".len()..].contains('/'));
            assert_eq!(restore_uri(&exposed), Some(("srv", uri.to_owned())));
        }
    }

    #[test]
    fn foreign_or_broken_uris_are_rejected() {
        assert_eq!(restore_uri("file:///x"), None);
        assert_eq!(restore_uri("toolward://srv"), None);
        assert_eq!(restore_uri("toolward://srv/%zz"), None);
        assert_eq!(restore_uri("toolward://srv/%FF"), None);
    }
}
