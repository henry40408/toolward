//! Drives the proxy in-process against a minimal streamable HTTP MCP server
//! that answers every POST with a plain JSON body.

use std::sync::{Arc, Mutex};

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams, ResourceContents,
};
use rmcp::service::{RoleClient, RoleServer, RunningService};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use toolward::proxy::Proxy;
use toolward::store::{CredentialStore, MemoryStore};
use toolward::upstream::{HttpConnector, HttpSpec, Upstream};

const LONG_TOOL: &str = "create_pull_request_review_comment_thread_reply";

#[derive(Default)]
struct Fake {
    tools: Mutex<Vec<String>>,
    /// Authorization headers seen, in order.
    authorizations: Mutex<Vec<String>>,
    /// Answer every request with this status and echo the Authorization header.
    fail_with: Mutex<Option<u16>>,
    /// protocolVersion of each initialize request.
    versions: Mutex<Vec<String>>,
    /// Answer `server/discover` with this HTTP status instead of a JSON-RPC error.
    discover_status: Mutex<Option<u16>>,
}

async fn read_request(
    stream: &mut tokio::net::TcpStream,
) -> Option<(String, Vec<(String, String)>, String)> {
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((
        request_line,
        headers,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

async fn respond(stream: &mut tokio::net::TcpStream, status: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn result_for(fake: &Fake, method: &str, params: &Value, authorization: &str) -> Value {
    match method {
        "initialize" => {
            let version = params["protocolVersion"].as_str().unwrap_or_default();
            fake.versions.lock().unwrap().push(version.to_owned());
            json!({
            "protocolVersion": params["protocolVersion"],
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "fake-http", "version": "0"},
            })
        }
        "tools/list" => {
            let tools: Vec<Value> = fake
                .tools
                .lock()
                .unwrap()
                .iter()
                .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
                .collect();
            json!({"tools": tools})
        }
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or_default();
            let text = if name == "whoami" {
                authorization.to_owned()
            } else {
                format!("called {name}")
            };
            json!({
                "content": [{"type": "text", "text": text}],
                "structuredContent": {"seen": authorization},
            })
        }
        "resources/list" => json!({"resources": [
            {"uri": "file:///a b/notes.txt?x=1", "name": "notes"},
        ]}),
        "resources/read" => json!({"contents": [
            {"uri": params["uri"], "mimeType": "text/plain", "text": format!("hello{authorization}")},
        ]}),
        "prompts/list" => json!({"prompts": [{"name": "greet"}]}),
        "prompts/get" => json!({"messages": [{
            "role": "user",
            "content": {"type": "text", "text": format!("prompt {}{authorization}", params["name"].as_str().unwrap_or_default())},
        }]}),
        _ => Value::Null,
    }
}

async fn serve_fake(fake: Arc<Fake>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let fake = Arc::clone(&fake);
            tokio::spawn(async move {
                let Some((request_line, headers, body)) = read_request(&mut stream).await else {
                    return;
                };
                let authorization = headers
                    .iter()
                    .find(|(k, _)| k == "authorization")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                fake.authorizations
                    .lock()
                    .unwrap()
                    .push(authorization.clone());
                let failing = *fake.fail_with.lock().unwrap();
                if let Some(status) = failing {
                    let body = format!("rejected {authorization}");
                    return respond(&mut stream, status, &body).await;
                }
                if !request_line.starts_with("POST") {
                    return respond(&mut stream, 405, "").await;
                }
                let message: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let Some(id) = message.get("id") else {
                    return respond(&mut stream, 202, "").await;
                };
                let method = message["method"].as_str().unwrap_or_default();
                // A legacy server does not know the stateless probe.
                if method == "server/discover" {
                    let discover_status = *fake.discover_status.lock().unwrap();
                    if let Some(status) = discover_status {
                        return respond(&mut stream, status, "unavailable").await;
                    }
                    let error = json!({"code": -32601, "message": "Method not found"});
                    let reply = json!({"jsonrpc": "2.0", "id": id, "error": error});
                    return respond(&mut stream, 200, &reply.to_string()).await;
                }
                let result = result_for(&fake, method, &message["params"], &authorization);
                let reply = json!({"jsonrpc": "2.0", "id": id, "result": result});
                respond(&mut stream, 200, &reply.to_string()).await;
            });
        }
    });
    url
}

struct Harness {
    client: RunningService<RoleClient, ()>,
    _server: RunningService<RoleServer, Proxy>,
}

fn http_upstream(
    name: &str,
    url: &str,
    headers: &[(&str, &str)],
    store: &Arc<dyn CredentialStore>,
) -> Upstream {
    let spec = HttpSpec {
        url: url.to_owned(),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    };
    Upstream::new(name, Box::new(HttpConnector::new(spec, Arc::clone(store))))
}

async fn start(upstreams: Vec<Upstream>) -> Harness {
    let proxy = Proxy::new(upstreams);
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    let serving = tokio::spawn(async move { proxy.serve(server_io).await });
    let client = ().serve(client_io).await.expect("client handshake");
    let server = serving.await.unwrap().expect("server handshake");
    Harness {
        client,
        _server: server,
    }
}

fn text_of(result: &rmcp::model::CallToolResult) -> String {
    serde_json::to_value(&result.content).unwrap()[0]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn fake_with_tools(tools: &[&str]) -> Arc<Fake> {
    let fake = Arc::new(Fake::default());
    *fake.tools.lock().unwrap() = tools.iter().map(|t| (*t).to_owned()).collect();
    fake
}

#[tokio::test]
async fn tools_are_prefixed_forwarded_and_get_the_secret_header() {
    let fake = fake_with_tools(&["echo", "whoami"]);
    let url = serve_fake(Arc::clone(&fake)).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::with(&[("tok", "s3cr3t")]));
    let upstream = http_upstream(
        "web",
        &url,
        &[("Authorization", "Bearer ${keychain:tok}")],
        &store,
    );
    let h = start(vec![upstream]).await;

    let tools = h.client.peer().list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(names, ["web__echo", "web__whoami"]);

    let result = h
        .client
        .peer()
        .call_tool(CallToolRequestParams::new("web__whoami"))
        .await
        .unwrap();
    // The upstream echoes the header it received; the agent must not see it.
    assert_eq!(text_of(&result), "Bearer [REDACTED]");
    let everything = serde_json::to_string(&result).unwrap();
    assert!(!everything.contains("s3cr3t"), "{everything}");
}

#[tokio::test]
async fn secrets_are_masked_in_resources_and_prompts() {
    let fake = fake_with_tools(&[]);
    let url = serve_fake(fake).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::with(&[("tok", "s3cr3t")]));
    let h = start(vec![http_upstream(
        "web",
        &url,
        &[("Authorization", "${keychain:tok}")],
        &store,
    )])
    .await;

    let resources = h.client.peer().list_all_resources().await.unwrap();
    let read = h
        .client
        .peer()
        .read_resource(ReadResourceRequestParams::new(resources[0].uri.clone()))
        .await
        .unwrap();
    let read = serde_json::to_string(&read).unwrap();
    assert!(read.contains("hello[REDACTED]"), "{read}");
    assert!(!read.contains("s3cr3t"), "{read}");

    let prompt = h
        .client
        .peer()
        .get_prompt(GetPromptRequestParams::new("web__greet"))
        .await
        .unwrap();
    let prompt = serde_json::to_string(&prompt).unwrap();
    assert!(prompt.contains("greet[REDACTED]"), "{prompt}");
    assert!(!prompt.contains("s3cr3t"), "{prompt}");
}

#[tokio::test]
async fn long_names_are_shortened_and_both_names_can_be_called() {
    let fake = fake_with_tools(&[LONG_TOOL, "short"]);
    let url = serve_fake(fake).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream("gh", &url, &[], &store)]).await;

    let tools = h.client.peer().list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let shortened = names
        .iter()
        .find(|n| n.starts_with("gh__create_pull_request"))
        .expect("shortened name");
    assert!(shortened.len() <= 49, "{shortened}");
    assert!(names.contains(&"gh__short".to_owned()));

    for name in [shortened.as_str(), &format!("gh__{LONG_TOOL}")] {
        let result = h
            .client
            .peer()
            .call_tool(CallToolRequestParams::new(name.to_owned()))
            .await
            .unwrap();
        assert_eq!(text_of(&result), format!("called {LONG_TOOL}"));
    }
}

#[tokio::test]
async fn an_unknown_tool_triggers_a_relist_before_failing() {
    let fake = fake_with_tools(&["old"]);
    let url = serve_fake(Arc::clone(&fake)).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream("web", &url, &[], &store)]).await;

    h.client.peer().list_all_tools().await.unwrap();
    fake.tools.lock().unwrap().push("fresh".to_owned());
    let result = h
        .client
        .peer()
        .call_tool(CallToolRequestParams::new("web__fresh"))
        .await
        .unwrap();
    assert_eq!(text_of(&result), "called fresh");

    let err = h
        .client
        .peer()
        .call_tool(CallToolRequestParams::new("web__nope"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown tool"), "{err}");
}

#[tokio::test]
async fn resources_round_trip_through_rewritten_uris() {
    let fake = fake_with_tools(&[]);
    let url = serve_fake(fake).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream("web", &url, &[], &store)]).await;

    let resources = h.client.peer().list_all_resources().await.unwrap();
    assert_eq!(resources.len(), 1);
    let exposed = resources[0].uri.clone();
    assert!(exposed.starts_with("toolward://web/"), "{exposed}");

    let read = h
        .client
        .peer()
        .read_resource(ReadResourceRequestParams::new(exposed.clone()))
        .await
        .unwrap();
    match &read.contents[0] {
        ResourceContents::TextResourceContents { uri, text, .. } => {
            assert_eq!(text, "hello");
            assert_eq!(*uri, exposed);
        }
        other => panic!("unexpected {other:?}"),
    }

    let err = h
        .client
        .peer()
        .read_resource(ReadResourceRequestParams::new("file:///etc/passwd"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown resource"), "{err}");
}

#[tokio::test]
async fn prompts_get_the_server_prefix() {
    let fake = fake_with_tools(&[]);
    let url = serve_fake(fake).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream("web", &url, &[], &store)]).await;

    let prompts = h.client.peer().list_all_prompts().await.unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "web__greet");

    let got = h
        .client
        .peer()
        .get_prompt(GetPromptRequestParams::new("web__greet"))
        .await
        .unwrap();
    let text = serde_json::to_string(&got.messages).unwrap();
    assert!(text.contains("prompt greet"), "{text}");
}

#[tokio::test]
async fn a_failing_http_upstream_is_skipped_and_never_leaks_the_secret() {
    let good = fake_with_tools(&["echo"]);
    let good_url = serve_fake(good).await;
    let bad = fake_with_tools(&["hidden"]);
    *bad.fail_with.lock().unwrap() = Some(500);
    let bad_url = serve_fake(Arc::clone(&bad)).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::with(&[("tok", "s3cr3t")]));
    let h = start(vec![
        http_upstream("good", &good_url, &[], &store),
        http_upstream(
            "bad",
            &bad_url,
            &[("Authorization", "Bearer ${keychain:tok}")],
            &store,
        ),
    ])
    .await;

    let tools = h.client.peer().list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(names, ["good__echo"]);

    let err = h
        .client
        .peer()
        .call_tool(CallToolRequestParams::new("bad__hidden"))
        .await
        .unwrap_err();
    assert!(!err.to_string().contains("s3cr3t"), "{err}");
    // The server did get the header; only our output is checked for leaks.
    assert!(
        bad.authorizations
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == "Bearer s3cr3t")
    );
}

#[tokio::test]
async fn a_missing_secret_makes_the_upstream_unavailable() {
    let fake = fake_with_tools(&["echo"]);
    let url = serve_fake(Arc::clone(&fake)).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream(
        "web",
        &url,
        &[("Authorization", "Bearer ${keychain:absent}")],
        &store,
    )])
    .await;

    assert!(h.client.peer().list_all_tools().await.unwrap().is_empty());
    let err = h
        .client
        .peer()
        .call_tool(CallToolRequestParams::new("web__echo"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("absent"), "{err}");
    // Nothing reached the server: the request was never built.
    assert!(fake.authorizations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn errors_after_the_handshake_are_redacted() {
    let fake = fake_with_tools(&["echo"]);
    let url = serve_fake(Arc::clone(&fake)).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::with(&[("tok", "s3cr3t")]));
    let h = start(vec![http_upstream(
        "web",
        &url,
        &[("Authorization", "Bearer ${keychain:tok}")],
        &store,
    )])
    .await;

    assert_eq!(h.client.peer().list_all_tools().await.unwrap().len(), 1);
    *fake.fail_with.lock().unwrap() = Some(500);
    let err = h
        .client
        .peer()
        .call_tool(CallToolRequestParams::new("web__echo"))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("HTTP 500"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");
}

#[tokio::test]
async fn a_tool_listed_twice_is_exposed_once() {
    let fake = fake_with_tools(&["dup", "dup", "other"]);
    let url = serve_fake(fake).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream("web", &url, &[], &store)]).await;

    let tools = h.client.peer().list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(names, ["web__dup", "web__other"]);
}

#[tokio::test]
async fn the_handshake_offers_a_version_that_has_initialize() {
    let fake = fake_with_tools(&[]);
    let url = serve_fake(Arc::clone(&fake)).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream("web", &url, &[], &store)]).await;

    h.client.peer().list_all_tools().await.unwrap();
    // rmcp's default, 2026-07-28, has no initialize; GitHub's server rejects it.
    assert_eq!(*fake.versions.lock().unwrap(), ["2025-11-25"]);
}

#[tokio::test]
async fn a_legacy_server_that_fails_the_probe_with_a_5xx_is_still_reached() {
    let fake = fake_with_tools(&["echo"]);
    *fake.discover_status.lock().unwrap() = Some(500);
    let url = serve_fake(Arc::clone(&fake)).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let h = start(vec![http_upstream("web", &url, &[], &store)]).await;

    let tools = h.client.peer().list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(*fake.versions.lock().unwrap(), ["2025-11-25"]);
}

/// A server that accepts connections and never answers.
async fn serve_silent() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    url
}

/// A fresh harness with one silent and one working upstream, so each listing
/// meets the silent one for the first time.
async fn with_silent_upstream() -> Harness {
    let silent = serve_silent().await;
    let fast = serve_fake(fake_with_tools(&["ping"])).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let hung = http_upstream("hung", &silent, &[], &store)
        .with_list_timeout(std::time::Duration::from_millis(500));
    start(vec![hung, http_upstream("fast", &fast, &[], &store)]).await
}

#[tokio::test]
async fn a_silent_upstream_does_not_hold_up_any_listing() {
    let limit = std::time::Duration::from_secs(10);

    let h = with_silent_upstream().await;
    let started = std::time::Instant::now();
    let tools = h.client.peer().list_all_tools().await.unwrap();
    assert!(started.elapsed() < limit);
    assert_eq!(tools.len(), 1);
    assert!(tools.iter().all(|t| t.name.starts_with("fast__")));

    let h = with_silent_upstream().await;
    let started = std::time::Instant::now();
    let resources = h.client.peer().list_all_resources().await.unwrap();
    assert!(started.elapsed() < limit);
    assert_eq!(resources.len(), 1);
    assert!(
        resources
            .iter()
            .all(|r| r.uri.starts_with("toolward://fast/"))
    );

    let h = with_silent_upstream().await;
    let started = std::time::Instant::now();
    let prompts = h.client.peer().list_all_prompts().await.unwrap();
    assert!(started.elapsed() < limit);
    assert_eq!(prompts.len(), 1);
    assert!(prompts.iter().all(|p| p.name.starts_with("fast__")));
}

#[tokio::test]
async fn check_tools_lists_exposed_names_and_flags_failures() {
    let fast = serve_fake(fake_with_tools(&["ping", LONG_TOOL])).await;
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let proxy = Proxy::new(vec![
        http_upstream("down", "http://127.0.0.1:1/mcp", &[], &store),
        http_upstream("fast", &fast, &[], &store),
    ]);
    let mut out = Vec::new();
    let all_listed = toolward::cli::check_tools(&proxy, &mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(!all_listed);
    assert!(text.contains("fast__ping"), "{text}");
    assert!(
        text.contains(&format!("(renamed from {LONG_TOOL:?})")),
        "{text}"
    );
    assert!(text.contains("ERROR"), "{text}");
}
