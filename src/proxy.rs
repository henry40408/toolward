//! The MCP server Claude Code talks to. It exposes the tools of every
//! upstream under a `<server>__<tool>` name and forwards calls.

use std::collections::BTreeMap;
use std::sync::Arc;

use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RoleServer, ServiceError};
use tokio::task::JoinSet;

use crate::config::{Config, Transport};
use crate::store::CredentialStore;
use crate::upstream::{StdioConnector, StdioSpec, Upstream, log};

/// Separates the server name from the tool name. Server names cannot contain it.
pub const SEPARATOR: &str = "__";

#[derive(Clone)]
pub struct Proxy {
    upstreams: Arc<BTreeMap<String, Arc<Upstream>>>,
}

impl Proxy {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        let map = upstreams
            .into_iter()
            .map(|upstream| (upstream.name().to_owned(), Arc::new(upstream)))
            .collect();
        Self {
            upstreams: Arc::new(map),
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
                Ok(Transport::Http { .. }) => {
                    log(format!(
                        "skipping {name:?}: http upstreams are not supported yet"
                    ));
                }
                Err(reason) => log(format!("skipping {name:?}: {reason}")),
            }
        }
        Self::new(upstreams)
    }

    pub async fn shutdown(&self) {
        let mut tasks = JoinSet::new();
        for upstream in self.upstreams.values() {
            let upstream = Arc::clone(upstream);
            tasks.spawn(async move { upstream.shutdown().await });
        }
        while tasks.join_next().await.is_some() {}
    }
}

fn service_error(err: ServiceError) -> McpError {
    match err {
        ServiceError::McpError(err) => err,
        other => McpError::internal_error(format!("upstream request failed: {other}"), None),
    }
}

impl ServerHandler for Proxy {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("toolward", env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tasks = JoinSet::new();
        for upstream in self.upstreams.values() {
            let upstream = Arc::clone(upstream);
            tasks.spawn(async move {
                let tools = match upstream.peer().await {
                    Ok(peer) => peer.list_all_tools().await.map_err(|err| err.to_string()),
                    Err(reason) => Err(reason),
                };
                (upstream.name().to_owned(), tools)
            });
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
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let (server, tool) = name
            .split_once(SEPARATOR)
            .ok_or_else(|| McpError::invalid_params(format!("unknown tool {name:?}"), None))?;
        let upstream = self
            .upstreams
            .get(server)
            .ok_or_else(|| McpError::invalid_params(format!("unknown tool {name:?}"), None))?;
        let peer = upstream.peer().await.map_err(|reason| {
            McpError::internal_error(
                format!("upstream {server:?} is unavailable: {reason}"),
                None,
            )
        })?;
        request.name = tool.to_owned().into();
        peer.call_tool_once(request).await.map_err(service_error)
    }
}
