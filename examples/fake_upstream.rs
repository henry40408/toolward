//! A tiny stdio MCP server used by the integration tests.
//!
//! Tools: `echo` returns its `text`, `env` returns the value of the environment
//! variable `name`, `fail` returns a tool-level error, `die` exits the process.

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
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
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: vec![
                Tool::new("echo", "Echo the text", schema("text")),
                Tool::new("env", "Read an environment variable", schema("name")),
                Tool::new("fail", "Always fails", schema("unused")),
                Tool::new("die", "Exits the process", schema("unused")),
            ],
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
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
