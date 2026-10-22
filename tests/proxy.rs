//! Drives the proxy in-process against a real child process
//! (`examples/fake_upstream.rs`) over an in-memory MCP connection.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::model::{CacheScope, CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RoleServer, RunningService};
use serde_json::json;

use toolward::proxy::Proxy;
use toolward::store::{CredentialStore, MemoryStore};
use toolward::upstream::{Connect, Hub, StdioConnector, StdioSpec, Upstream};

fn fake_upstream_path() -> String {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_toolward"));
    let examples = bin.parent().unwrap().join("examples");
    let name = format!("fake_upstream{}", std::env::consts::EXE_SUFFIX);
    let path = examples.join(name);
    assert!(
        path.exists(),
        "missing {}; run `cargo build --examples`",
        path.display()
    );
    path.to_string_lossy().into_owned()
}

/// An upstream that is built once the proxy's hub exists.
struct Pending {
    name: String,
    connector: Box<dyn Connect>,
    list_timeout: Option<Duration>,
}

impl Pending {
    fn new(name: &str, connector: impl Connect + 'static) -> Self {
        Self {
            name: name.to_owned(),
            connector: Box::new(connector),
            list_timeout: None,
        }
    }

    fn with_list_timeout(mut self, timeout: Duration) -> Self {
        self.list_timeout = Some(timeout);
        self
    }

    fn build(self, hub: &Arc<Hub>) -> Upstream {
        let upstream = Upstream::new(self.name, self.connector, Arc::clone(hub));
        match self.list_timeout {
            Some(timeout) => upstream.with_list_timeout(timeout),
            None => upstream,
        }
    }
}

fn proxy_of(pending: Vec<Pending>) -> Proxy {
    let hub = Arc::new(Hub::default());
    let upstreams = pending.into_iter().map(|p| p.build(&hub)).collect();
    Proxy::new(hub, upstreams)
}

fn stdio(
    name: &str,
    command: &str,
    env: &[(&str, &str)],
    store: &Arc<dyn CredentialStore>,
) -> Pending {
    let spec = StdioSpec {
        command: command.to_owned(),
        args: vec![],
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    };
    Pending::new(name, StdioConnector::new(name, spec, Arc::clone(store)))
}

struct Harness {
    client: RunningService<RoleClient, ()>,
    _server: RunningService<RoleServer, Proxy>,
    proxy: Proxy,
}

async fn start(upstreams: Vec<Pending>) -> Harness {
    let proxy = proxy_of(upstreams);
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    let serving = {
        let proxy = proxy.clone();
        tokio::spawn(async move { proxy.serve(server_io).await })
    };
    let client = ().serve(client_io).await.expect("client handshake");
    let server = serving.await.unwrap().expect("server handshake");
    Harness {
        client,
        _server: server,
        proxy,
    }
}

impl Harness {
    async fn tool_names(&self) -> Vec<String> {
        let tools = self.client.peer().list_all_tools().await.unwrap();
        tools.into_iter().map(|t| t.name.to_string()).collect()
    }

    async fn call(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<CallToolResult, rmcp::ServiceError> {
        let params = CallToolRequestParams::new(name.to_owned())
            .with_arguments(arguments.as_object().unwrap().clone());
        self.client.peer().call_tool(params).await
    }

    async fn finish(self) {
        self.proxy.shutdown().await;
    }
}

fn text_of(result: &CallToolResult) -> String {
    serde_json::to_string(&result.content).unwrap()
}

fn store_with(entries: &[(&str, &str)]) -> Arc<dyn CredentialStore> {
    Arc::new(MemoryStore::with(entries))
}

#[tokio::test]
async fn lists_prefixed_tools_and_forwards_calls() {
    let store = store_with(&[]);
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &[], &store)]).await;

    assert_eq!(
        harness.tool_names().await,
        [
            "fake__die",
            "fake__echo",
            "fake__env",
            "fake__fail",
            "fake__hang"
        ]
    );
    let result = harness
        .call("fake__echo", json!({"text": "hi"}))
        .await
        .unwrap();
    assert!(text_of(&result).contains("echo: hi"));
    harness.finish().await;
}

#[tokio::test]
async fn tool_level_errors_pass_through() {
    let store = store_with(&[]);
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &[], &store)]).await;

    let result = harness.call("fake__fail", json!({})).await.unwrap();
    assert_eq!(result.is_error, Some(true));
    assert!(text_of(&result).contains("boom"));
    harness.finish().await;
}

#[tokio::test]
async fn injects_secrets_into_the_child_environment_only() {
    let store = store_with(&[("tok", "s3cr3t-value")]);
    let env = [("FAKE_SECRET", "${keychain:tok}"), ("FAKE_PLAIN", "plain")];
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &env, &store)]).await;

    // The child sees the expanded value, but what it echoes back is masked.
    let result = harness
        .call("fake__env", json!({"name": "FAKE_SECRET"}))
        .await
        .unwrap();
    let echoed = text_of(&result);
    assert!(echoed.contains("[REDACTED]"), "{echoed}");
    assert!(!echoed.contains("s3cr3t-value"), "{echoed}");
    let result = harness
        .call("fake__env", json!({"name": "FAKE_PLAIN"}))
        .await
        .unwrap();
    assert!(text_of(&result).contains("plain"));
    // ...but the tool list the agent sees carries no secret.
    let listing =
        serde_json::to_string(&harness.client.peer().list_all_tools().await.unwrap()).unwrap();
    assert!(!listing.contains("s3cr3t-value"));
    harness.finish().await;
}

#[tokio::test]
async fn failing_upstreams_are_skipped() {
    let store = store_with(&[]);
    let upstreams = vec![
        stdio("broken", "/nonexistent/toolward-test-binary", &[], &store),
        stdio("fake", &fake_upstream_path(), &[], &store),
        // References a secret that is not stored.
        stdio(
            "nosecret",
            &fake_upstream_path(),
            &[("X", "${keychain:absent}")],
            &store,
        ),
    ];
    let harness = start(upstreams).await;

    assert_eq!(
        harness.tool_names().await,
        [
            "fake__die",
            "fake__echo",
            "fake__env",
            "fake__fail",
            "fake__hang"
        ]
    );

    let err = harness
        .call("broken__echo", json!({}))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("unavailable"), "{err}");
    let err = harness
        .call("nosecret__echo", json!({}))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("absent"), "{err}");
    harness.finish().await;
}

#[tokio::test]
async fn a_slow_listing_is_skipped() {
    let store = store_with(&[]);
    let slow = stdio(
        "slow",
        &fake_upstream_path(),
        &[("FAKE_LIST_DELAY_MS", "30000")],
        &store,
    )
    .with_list_timeout(Duration::from_millis(1500));
    let fast = stdio("fast", &fake_upstream_path(), &[], &store);
    let harness = start(vec![slow, fast]).await;

    let started = std::time::Instant::now();
    let names = harness.tool_names().await;
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(names.iter().all(|name| name.starts_with("fast__")));
    assert!(!names.is_empty());
    harness.finish().await;
}

#[tokio::test]
async fn cancelling_a_call_cancels_it_upstream() {
    let store = store_with(&[]);
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &[], &store)]).await;
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");

    let params = CallToolRequestParams::new("fake__hang")
        .with_arguments(json!({"marker": marker}).as_object().unwrap().clone());
    let request =
        rmcp::model::ClientRequest::CallToolRequest(rmcp::model::CallToolRequest::new(params));
    let handle = harness
        .client
        .peer()
        .send_cancellable_request(request, rmcp::service::PeerRequestOptions::no_options())
        .await
        .unwrap();
    // Let the call reach the upstream before cancelling it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    handle.cancel(Some("test".into())).await.unwrap();

    let mut cancelled = false;
    for _ in 0..50 {
        if marker.exists() {
            cancelled = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(cancelled, "the upstream never saw the cancellation");
    harness.finish().await;
}

#[tokio::test]
async fn reconnects_after_the_upstream_process_dies() {
    let store = store_with(&[]);
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &[], &store)]).await;

    assert!(
        harness
            .call("fake__echo", json!({"text": "a"}))
            .await
            .is_ok()
    );
    // The child exits without answering.
    assert!(harness.call("fake__die", json!({})).await.is_err());

    // The next call may race with the proxy noticing the exit; it must recover.
    let mut recovered = false;
    for _ in 0..40 {
        if let Ok(result) = harness.call("fake__echo", json!({"text": "b"})).await {
            assert!(text_of(&result).contains("echo: b"));
            recovered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(recovered, "upstream was never reconnected");
    harness.finish().await;
}

#[tokio::test]
async fn unknown_tools_are_rejected() {
    let store = store_with(&[]);
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &[], &store)]).await;

    for name in ["echo", "nope__echo", "fake__nope"] {
        assert!(harness.call(name, json!({})).await.is_err(), "{name}");
    }
    harness.finish().await;
}

/// The hints of the tool list the agent receives.
async fn tool_list_hints(harness: &Harness) -> (Option<u64>, Option<CacheScope>) {
    let list = harness.client.peer().list_tools(None).await.unwrap();
    (list.ttl_ms, list.cache_scope)
}

#[tokio::test]
async fn a_list_without_hints_is_passed_on_as_uncacheable() {
    let store = store_with(&[]);
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &[], &store)]).await;

    assert_eq!(
        tool_list_hints(&harness).await,
        (Some(0), Some(CacheScope::Private))
    );
    harness.finish().await;
}

#[tokio::test]
async fn the_hints_of_one_upstream_reach_the_agent() {
    let store = store_with(&[]);
    let env = [("FAKE_TTL_MS", "60000"), ("FAKE_CACHE_SCOPE", "public")];
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &env, &store)]).await;

    assert_eq!(
        tool_list_hints(&harness).await,
        (Some(60_000), Some(CacheScope::Public))
    );
    harness.finish().await;
}

#[tokio::test]
async fn merged_lists_get_the_weakest_hint() {
    let store = store_with(&[]);
    let long_public = [("FAKE_TTL_MS", "60000"), ("FAKE_CACHE_SCOPE", "public")];
    let short_private = [("FAKE_TTL_MS", "5000"), ("FAKE_CACHE_SCOPE", "private")];
    let harness = start(vec![
        stdio("a", &fake_upstream_path(), &long_public, &store),
        stdio("b", &fake_upstream_path(), &short_private, &store),
    ])
    .await;

    assert_eq!(
        tool_list_hints(&harness).await,
        (Some(5_000), Some(CacheScope::Private))
    );
    harness.finish().await;
}

#[tokio::test]
async fn a_list_missing_an_upstream_is_not_cacheable() {
    let store = store_with(&[]);
    let env = [("FAKE_TTL_MS", "60000"), ("FAKE_CACHE_SCOPE", "public")];
    let harness = start(vec![
        stdio("fake", &fake_upstream_path(), &env, &store),
        stdio("broken", "/nonexistent/toolward-test-binary", &[], &store),
    ])
    .await;

    assert_eq!(
        tool_list_hints(&harness).await,
        (Some(0), Some(CacheScope::Private))
    );
    harness.finish().await;
}

#[tokio::test]
async fn an_upstream_without_tools_does_not_limit_the_hint() {
    let store = store_with(&[]);
    let env = [("FAKE_TTL_MS", "60000"), ("FAKE_CACHE_SCOPE", "public")];
    let harness = start(vec![
        stdio("fake", &fake_upstream_path(), &env, &store),
        stdio(
            "promptsonly",
            &fake_upstream_path(),
            &[("FAKE_NO_TOOLS", "1")],
            &store,
        ),
    ])
    .await;

    assert_eq!(
        tool_list_hints(&harness).await,
        (Some(60_000), Some(CacheScope::Public))
    );
    harness.finish().await;
}

#[tokio::test]
async fn resource_templates_carry_hints() {
    let store = store_with(&[]);
    let harness = start(vec![stdio("fake", &fake_upstream_path(), &[], &store)]).await;

    let list = harness
        .client
        .peer()
        .list_resource_templates(None)
        .await
        .unwrap();
    assert_eq!(
        (list.ttl_ms, list.cache_scope),
        (Some(0), Some(CacheScope::Private))
    );
    harness.finish().await;
}
