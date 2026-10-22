//! A tiny stdio MCP server used by the integration tests.
//!
//! Tools: `echo` returns its `text`, `env` returns the value of the environment
//! variable `name`, `fail` returns a tool-level error, `die` exits the process, `hang`
//! waits for cancellation and then writes the file named by `marker`.
//!
//! `FAKE_TTL_MS` and `FAKE_CACHE_SCOPE` (`public` or `private`) set the caching
//! hints of the tool list. Without them the list carries none. `FAKE_NO_TOOLS`
//! makes it announce prompts only, and refuse `tools/list`.

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServiceExt};
use serde_json::json;

struct Fake;

fn schema(property: &str) -> serde_json::Map<String, serde_json::Value> {
    json!({
        "type": "object",
        "properties": { property: { "type": "string" } },
    })
    .as_object()
    .unwrap()
    .clone()
}

impl ServerHandler for Fake {
    fn get_info(&self) -> ServerConfig {
        let capabilities = if std::env::var("FAKE_NO_TOOLS").is_ok() {
            ServerCapabilities::builder().enable_prompts().build()
        } else {
            ServerCapabilities::builder().enable_tools().build()
        };
        ServerConfig::new(capabilities)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        if std::env::var("FAKE_NO_TOOLS").is_ok() {
            return Err(McpError::method_not_found::<
                rmcp::model::ListToolsRequestMethod,
            >());
        }
        // `FAKE_LIST_DELAY_MS` makes the listing slow.
        if let Some(ms) = std::env::var("FAKE_LIST_DELAY_MS")
            .ok()
            .and_then(|ms| ms.parse().ok())
        {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        let mut result = ListToolsResult {
            tools: vec![
                Tool::new("echo", "Echo the text", schema("text")),
                Tool::new("env", "Read an environment variable", schema("name")),
                Tool::new("fail", "Always fails", schema("unused")),
                Tool::new("die", "Exits the process", schema("unused")),
                Tool::new("hang", "Waits to be cancelled", schema("marker")),
            ],
            ..Default::default()
        };
        result.ttl_ms = std::env::var("FAKE_TTL_MS")
            .ok()
            .and_then(|ms| ms.parse().ok());
        result.cache_scope = match std::env::var("FAKE_CACHE_SCOPE").as_deref() {
            Ok("public") => Some(CacheScope::Public),
            Ok("private") => Some(CacheScope::Private),
            _ => None,
        };
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let argument = |key: &str| {
            request
                .arguments
                .as_ref()
                .and_then(|args| args.get(key))
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned()
        };
        let result = match request.name.as_ref() {
            "echo" => CallToolResult::success(vec![ContentBlock::text(format!(
                "echo: {}",
                argument("text")
            ))]),
            "env" => {
                let value = std::env::var(argument("name")).unwrap_or_else(|_| "<unset>".into());
                CallToolResult::success(vec![ContentBlock::text(value)])
            }
            "fail" => CallToolResult::error(vec![ContentBlock::text("boom")]),
            "die" => std::process::exit(0),
            "hang" => {
                // Leaves a marker file once the request is cancelled.
                context.ct.cancelled().await;
                std::fs::write(argument("marker"), "cancelled").expect("write marker");
                CallToolResult::success(vec![ContentBlock::text("cancelled")])
            }
            other => {
                return Err(McpError::invalid_params(format!("no tool {other:?}"), None));
            }
        };
        Ok(result.into())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Fake.serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}
