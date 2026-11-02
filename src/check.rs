//! The report `toolward check` prints: one block per server.
//!
//! The checks collect plain facts into `ServerReport`s. `render` turns them
//! into text for people and `render_json` into JSON for programs; the two
//! have different readers and share only the facts.

use std::io::{self, Write};

use rmcp::model::{ServerCapabilities, ServerPeerInfo};
use serde::Serialize;
use serde_json::Value;

use crate::config::Config;
use crate::names::SEPARATOR;
use crate::oauth;
use crate::proxy::Proxy;
use crate::store::CredentialStore;
use crate::upstream::Upstream;

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStatus {
    Ok,
    Missing,
    Error,
}

/// Whether one secret is in the credential store. Holds no secret value.
#[derive(Serialize)]
pub struct SecretReport {
    /// The credential store entry, as in `${keychain:<account>}`.
    pub account: String,
    pub status: SecretStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OauthStatus {
    LoggedIn,
    NotLoggedIn,
    Error,
}

#[derive(Serialize)]
pub struct OauthReport {
    pub status: OauthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct ToolReport {
    /// The name the agent sees, with the `<server>__` prefix.
    pub name: String,
    /// The name the upstream server gave it.
    pub original: String,
}

/// What connecting to the upstream showed.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UpstreamReport {
    Ok {
        protocol: Option<String>,
        server: Option<String>,
        capabilities: Vec<String>,
        tools: Vec<ToolReport>,
    },
    Error {
        reason: String,
    },
}

pub struct ServerReport {
    pub name: String,
    pub secrets: Vec<SecretReport>,
    /// `None` when the server does not use OAuth.
    pub oauth: Option<OauthReport>,
    /// `None` until `check_tools` ran.
    pub upstream: Option<UpstreamReport>,
}

impl ServerReport {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            secrets: Vec::new(),
            oauth: None,
            upstream: None,
        }
    }

    fn is_ok(&self) -> bool {
        self.secrets
            .iter()
            .all(|secret| secret.status == SecretStatus::Ok)
            && self
                .oauth
                .as_ref()
                .is_none_or(|oauth| oauth.status == OauthStatus::LoggedIn)
            && !matches!(self.upstream, Some(UpstreamReport::Error { .. }))
    }
}

pub fn all_ok(reports: &[ServerReport]) -> bool {
    reports.iter().all(ServerReport::is_ok)
}

/// Checks that every referenced secret and OAuth login is in the store.
/// Never reads a secret value.
pub fn check_secrets(config: &Config, store: &dyn CredentialStore) -> Vec<ServerReport> {
    let mut reports = Vec::new();
    for (server, accounts) in config.references() {
        let mut report = ServerReport::new(server);
        if config.oauth_servers().any(|name| name == server) {
            report.oauth = Some(oauth_report(store, server));
        }
        report.secrets = accounts
            .iter()
            .map(|account| secret_report(store, account))
            .collect();
        reports.push(report);
    }
    reports
}

fn oauth_report(store: &dyn CredentialStore, server: &str) -> OauthReport {
    let (status, reason) = match oauth::is_logged_in(store, server) {
        Ok(true) => (OauthStatus::LoggedIn, None),
        Ok(false) => (OauthStatus::NotLoggedIn, None),
        Err(err) => (OauthStatus::Error, Some(err.to_string())),
    };
    OauthReport { status, reason }
}

fn secret_report(store: &dyn CredentialStore, account: &str) -> SecretReport {
    let (status, reason) = match store.get(account) {
        Ok(Some(_)) => (SecretStatus::Ok, None),
        Ok(None) => (SecretStatus::Missing, None),
        Err(err) => (SecretStatus::Error, Some(err.to_string())),
    };
    SecretReport {
        account: account.to_owned(),
        status,
        reason,
    }
}

/// Connects to every upstream and adds what it announced (protocol version,
/// server, capabilities) and the tool names the agent will see.
pub async fn check_tools(proxy: &Proxy, reports: &mut Vec<ServerReport>) {
    for upstream in proxy.upstreams() {
        let report = report_for(reports, upstream.name());
        report.upstream = Some(match upstream.tools().await {
            Ok(_) => {
                let info = upstream.list_peer().await.ok().and_then(|p| p.peer_info());
                announced(upstream, info.as_deref())
            }
            Err(reason) => UpstreamReport::Error {
                reason: upstream.redact(&reason),
            },
        });
    }
    proxy.shutdown().await;
}

fn report_for<'a>(reports: &'a mut Vec<ServerReport>, name: &str) -> &'a mut ServerReport {
    let index = reports
        .iter()
        .position(|report| report.name == name)
        .unwrap_or_else(|| {
            reports.push(ServerReport::new(name));
            reports.len() - 1
        });
    &mut reports[index]
}

fn announced(upstream: &Upstream, info: Option<&ServerPeerInfo>) -> UpstreamReport {
    let server = info
        .and_then(|info| info.server_info.as_ref())
        .map(|server| {
            let text = format!("{} {}", server.name, server.version);
            // Server text must not start a line of its own.
            upstream.redact(&text.replace(char::is_control, "?"))
        });
    UpstreamReport::Ok {
        protocol: info.map(|info| upstream.redact(&info.protocol_version.to_string())),
        server,
        capabilities: info
            .map(|info| capability_names(&info.capabilities))
            .unwrap_or_default()
            .iter()
            .map(|name| upstream.redact(name))
            .collect(),
        tools: tool_reports(upstream),
    }
}

fn tool_reports(upstream: &Upstream) -> Vec<ToolReport> {
    let name = upstream.name();
    upstream
        .tool_names()
        .into_iter()
        .map(|(exposed, original)| ToolReport {
            name: format!("{name}{SEPARATOR}{exposed}"),
            original,
        })
        .collect()
}

/// The capabilities and extensions a server declares, such as `tools` or
/// `io.modelcontextprotocol/tasks`, sorted by name.
fn capability_names(capabilities: &ServerCapabilities) -> Vec<String> {
    let Ok(Value::Object(fields)) = serde_json::to_value(capabilities) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for (key, value) in fields {
        match (key.as_str(), value) {
            (_, Value::Null) => {}
            ("extensions", Value::Object(extensions)) => names.extend(extensions.keys().cloned()),
            (_, _) => names.push(key),
        }
    }
    names.sort();
    names
}

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// Wraps `text` in an ANSI color when `color` is on.
fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}{RESET}")
    } else {
        text.to_owned()
    }
}

/// Whether to color the report: only on a terminal, and not when the user
/// set `NO_COLOR` (<https://no-color.org>).
pub fn wants_color(stdout_is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    stdout_is_terminal && no_color.is_none_or(|value| value.is_empty())
}

/// One line of the text report: what was checked and how it went.
struct Finding {
    ok: bool,
    text: String,
    /// A command that solves the problem.
    fix: Option<String>,
}

impl Finding {
    fn ok(text: impl Into<String>) -> Self {
        Self {
            ok: true,
            text: text.into(),
            fix: None,
        }
    }

    fn problem(text: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            ok: false,
            text: text.into(),
            fix,
        }
    }
}

fn findings(report: &ServerReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    if report.secrets.is_empty() {
        findings.push(Finding::ok("no secret references"));
    }
    if let Some(oauth) = &report.oauth {
        findings.push(oauth_finding(&report.name, oauth));
    }
    findings.extend(report.secrets.iter().map(secret_finding));
    match &report.upstream {
        None => {}
        Some(UpstreamReport::Error { reason }) => {
            findings.push(Finding::problem(
                format!("tools unavailable: {reason}"),
                None,
            ));
        }
        Some(UpstreamReport::Ok {
            protocol,
            server,
            capabilities,
            tools,
        }) => {
            if let Some(protocol) = protocol {
                findings.push(Finding::ok(announcement(protocol, server, capabilities)));
            }
            let count = tools.len();
            findings.push(Finding::ok(format!(
                "{count} {}",
                plural(count, "tool", "tools")
            )));
        }
    }
    findings
}

fn oauth_finding(server: &str, oauth: &OauthReport) -> Finding {
    match oauth.status {
        OauthStatus::LoggedIn => Finding::ok("oauth logged in"),
        OauthStatus::NotLoggedIn => Finding::problem(
            "oauth not logged in",
            Some(format!("toolward auth login {server}")),
        ),
        OauthStatus::Error => Finding::problem(
            format!(
                "oauth error: {}",
                oauth.reason.as_deref().unwrap_or_default()
            ),
            None,
        ),
    }
}

fn secret_finding(secret: &SecretReport) -> Finding {
    let account = &secret.account;
    match secret.status {
        SecretStatus::Ok => Finding::ok(account),
        SecretStatus::Missing => Finding::problem(
            format!("{account} missing"),
            Some(format!("toolward secret set {account}")),
        ),
        SecretStatus::Error => Finding::problem(
            format!(
                "{account} error: {}",
                secret.reason.as_deref().unwrap_or_default()
            ),
            None,
        ),
    }
}

/// What a server announced, on one line.
fn announcement(protocol: &str, server: &Option<String>, capabilities: &[String]) -> String {
    let mut parts = vec![format!("protocol {protocol}")];
    parts.extend(server.clone());
    parts.push(if capabilities.is_empty() {
        "(none)".to_owned()
    } else {
        capabilities.join(", ")
    });
    parts.join(" · ")
}

/// The tool names of a server, marking those that were renamed.
fn tool_lines(report: &ServerReport) -> Vec<String> {
    let Some(UpstreamReport::Ok { tools, .. }) = &report.upstream else {
        return Vec::new();
    };
    tools
        .iter()
        .map(|tool| {
            let unchanged = format!("{}{SEPARATOR}{}", report.name, tool.original);
            if tool.name == unchanged {
                tool.name.clone()
            } else {
                format!("{}  (renamed from {:?})", tool.name, tool.original)
            }
        })
        .collect()
}

/// Prints one block per server and a summary line.
/// `tools_checked` tells whether `check_tools` ran; `color` adds ANSI colors.
pub fn render(
    reports: &[ServerReport],
    tools_checked: bool,
    color: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    for report in reports {
        writeln!(out, "{}", report.name)?;
        for finding in findings(report) {
            let mark = if finding.ok {
                paint(color, GREEN, "✓")
            } else {
                paint(color, RED, "✗")
            };
            writeln!(out, "  {mark} {}", finding.text)?;
            if let Some(fix) = &finding.fix {
                writeln!(out, "      {}", paint(color, DIM, &format!("fix: {fix}")))?;
            }
        }
        for tool in tool_lines(report) {
            writeln!(out, "      {tool}")?;
        }
        writeln!(out)?;
    }
    writeln!(out, "{}", summary(reports, tools_checked))
}

#[derive(Serialize)]
struct JsonReport<'a> {
    ok: bool,
    servers: Vec<JsonServer<'a>>,
}

#[derive(Serialize)]
struct JsonServer<'a> {
    name: &'a str,
    ok: bool,
    secrets: &'a [SecretReport],
    oauth: Option<&'a OauthReport>,
    upstream: Option<&'a UpstreamReport>,
}

/// Prints the facts as one JSON object on one line. Never colored.
pub fn render_json(reports: &[ServerReport], out: &mut dyn Write) -> io::Result<()> {
    let report = JsonReport {
        ok: all_ok(reports),
        servers: reports
            .iter()
            .map(|report| JsonServer {
                name: &report.name,
                ok: report.is_ok(),
                secrets: &report.secrets,
                oauth: report.oauth.as_ref(),
                upstream: report.upstream.as_ref(),
            })
            .collect(),
    };
    serde_json::to_writer(&mut *out, &report)?;
    writeln!(out)
}

fn summary(reports: &[ServerReport], tools_checked: bool) -> String {
    let total = reports.len();
    let with_problems = reports.iter().filter(|report| !report.is_ok()).count();
    let servers = plural(total, "server", "servers");
    let mut line = if with_problems == 0 {
        format!("{total} {servers}, all ok")
    } else {
        let problems = plural(with_problems, "problem", "problems");
        format!("{total} {servers}, {with_problems} with {problems}")
    };
    if !tools_checked {
        line.push_str(" (run with --tools to also connect)");
    }
    line
}

fn plural<'a>(count: usize, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 { one } else { many }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, StoreError};

    const CONFIG: &str = r#"{"mcpServers": {
        "a": {"command": "x", "env": {"T": "${keychain:present}"}},
        "b": {"command": "y", "env": {"T": "${keychain:absent}"}},
        "c": {"command": "z"}
    }}"#;

    fn rendered(tools_checked: bool) -> (bool, String) {
        let store = MemoryStore::with(&[("present", "TOPSECRET")]);
        let reports = check_secrets(&Config::parse(CONFIG).unwrap(), &store);
        let mut out = Vec::new();
        render(&reports, tools_checked, false, &mut out).unwrap();
        (all_ok(&reports), String::from_utf8(out).unwrap())
    }

    #[test]
    fn capability_names_include_extensions_and_skip_unset_ones() {
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_prompts()
            .enable_tasks()
            .build();
        assert_eq!(
            capability_names(&capabilities),
            ["io.modelcontextprotocol/tasks", "prompts", "tools"]
        );
        assert!(capability_names(&ServerCapabilities::default()).is_empty());
    }

    #[test]
    fn secrets_are_reported_without_leaking_values() {
        let (all_ok, text) = rendered(false);
        assert!(!all_ok);
        assert!(text.contains("✓ present"), "{text}");
        assert!(text.contains("✗ absent missing"), "{text}");
        assert!(text.contains("no secret references"), "{text}");
        assert!(!text.contains("TOPSECRET"), "{text}");
    }

    #[test]
    fn a_problem_comes_with_its_fix() {
        let (_, text) = rendered(false);
        assert!(text.contains("fix: toolward secret set absent"), "{text}");
    }

    #[test]
    fn summary_counts_servers_with_problems() {
        let (_, text) = rendered(false);
        assert!(
            text.ends_with("3 servers, 1 with problem (run with --tools to also connect)\n"),
            "{text}"
        );
        let (_, text) = rendered(true);
        assert!(text.ends_with("3 servers, 1 with problem\n"), "{text}");
    }

    #[test]
    fn color_marks_the_status_and_leaves_the_text_readable() {
        let store = MemoryStore::with(&[("present", "x")]);
        let reports = check_secrets(&Config::parse(CONFIG).unwrap(), &store);
        let mut out = Vec::new();
        render(&reports, true, true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\x1b[32m✓\x1b[0m present"), "{text}");
        assert!(text.contains("\x1b[31m✗\x1b[0m absent missing"), "{text}");
        assert!(rendered(true).1.find('\x1b').is_none());
    }

    #[test]
    fn color_needs_a_terminal_and_no_no_color() {
        use std::ffi::OsStr;
        assert!(wants_color(true, None));
        assert!(wants_color(true, Some(OsStr::new(""))));
        assert!(!wants_color(true, Some(OsStr::new("1"))));
        assert!(!wants_color(false, None));
    }

    #[test]
    fn json_holds_the_facts_and_no_secret_value() {
        let store = MemoryStore::with(&[("present", "TOPSECRET")]);
        let reports = check_secrets(&Config::parse(CONFIG).unwrap(), &store);
        let mut out = Vec::new();
        render_json(&reports, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains("TOPSECRET") && !text.contains('\x1b'),
            "{text}"
        );
        assert!(
            text.ends_with("}\n") && text.matches('\n').count() == 1,
            "{text}"
        );
        let json: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["ok"], false);
        let servers = json["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0]["name"], "a");
        assert_eq!(servers[0]["ok"], true);
        assert_eq!(
            servers[0]["secrets"][0],
            serde_json::json!({"account": "present", "status": "ok"})
        );
        assert_eq!(servers[1]["ok"], false);
        assert_eq!(servers[1]["secrets"][0]["status"], "missing");
        assert_eq!(servers[2]["secrets"], serde_json::json!([]));
        assert!(servers[0]["oauth"].is_null() && servers[0]["upstream"].is_null());
    }

    /// A store that answers every `get` the same way.
    struct FixedStore(Result<Option<&'static str>, &'static str>);

    impl CredentialStore for FixedStore {
        fn get(&self, _account: &str) -> Result<Option<String>, StoreError> {
            match self.0 {
                Ok(secret) => Ok(secret.map(str::to_owned)),
                Err(message) => Err(StoreError::Backend(message.to_owned())),
            }
        }

        fn set(&self, _account: &str, _secret: &str) -> Result<(), StoreError> {
            unreachable!("check never writes")
        }

        fn delete(&self, _account: &str) -> Result<bool, StoreError> {
            unreachable!("check never writes")
        }
    }

    const OAUTH_CONFIG: &str = r#"{"mcpServers": {
        "s": {"url": "https://x/mcp", "oauth": {}},
        "t": {"command": "x", "env": {"T": "${keychain:token}"}}
    }}"#;

    fn text_of(reports: &[ServerReport]) -> String {
        let mut out = Vec::new();
        render(reports, true, false, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn json_of(reports: &[ServerReport]) -> Value {
        let mut out = Vec::new();
        render_json(reports, &mut out).unwrap();
        serde_json::from_slice(&out).unwrap()
    }

    fn reports_with(store: &dyn CredentialStore) -> Vec<ServerReport> {
        check_secrets(&Config::parse(OAUTH_CONFIG).unwrap(), store)
    }

    #[test]
    fn oauth_logged_in_is_ok() {
        let reports = reports_with(&FixedStore(Ok(Some("x"))));
        let text = text_of(&reports);
        assert!(text.contains("✓ oauth logged in"), "{text}");
        assert!(all_ok(&reports));
        assert_eq!(
            json_of(&reports)["servers"][0]["oauth"]["status"],
            "logged_in"
        );
    }

    #[test]
    fn oauth_not_logged_in_names_the_login_command() {
        let reports = reports_with(&FixedStore(Ok(None)));
        let text = text_of(&reports);
        assert!(text.contains("✗ oauth not logged in"), "{text}");
        assert!(text.contains("fix: toolward auth login s"), "{text}");
        let json = json_of(&reports);
        assert_eq!(json["servers"][0]["oauth"]["status"], "not_logged_in");
        assert!(json["servers"][0]["oauth"].get("reason").is_none());
    }

    #[test]
    fn store_failures_are_reported_for_oauth_and_secrets() {
        let reports = reports_with(&FixedStore(Err("locked")));
        let text = text_of(&reports);
        assert!(!all_ok(&reports));
        assert!(
            text.contains("✗ oauth error: credential store failure: locked"),
            "{text}"
        );
        assert!(
            text.contains("✗ token error: credential store failure: locked"),
            "{text}"
        );
        let json = json_of(&reports);
        assert_eq!(json["servers"][0]["oauth"]["status"], "error");
        assert_eq!(
            json["servers"][1]["secrets"][0]["reason"],
            "credential store failure: locked"
        );
    }

    fn report_with_upstream(upstream: UpstreamReport) -> ServerReport {
        ServerReport {
            name: "s".into(),
            secrets: Vec::new(),
            oauth: None,
            upstream: Some(upstream),
        }
    }

    #[test]
    fn a_connected_upstream_shows_what_it_announced() {
        let report = report_with_upstream(UpstreamReport::Ok {
            protocol: Some("2025-06-18".into()),
            server: Some("srv 1.0".into()),
            capabilities: vec!["prompts".into(), "tools".into()],
            tools: vec![
                ToolReport {
                    name: "s__ping".into(),
                    original: "ping".into(),
                },
                ToolReport {
                    name: "s__short_x1".into(),
                    original: "a_very_long_name".into(),
                },
            ],
        });
        let text = text_of(std::slice::from_ref(&report));
        assert!(
            text.contains("✓ protocol 2025-06-18 · srv 1.0 · prompts, tools"),
            "{text}"
        );
        assert!(text.contains("✓ 2 tools"), "{text}");
        assert!(text.contains("      s__ping\n"), "{text}");
        assert!(
            text.contains(r#"s__short_x1  (renamed from "a_very_long_name")"#),
            "{text}"
        );
        let json = json_of(&[report]);
        let upstream = &json["servers"][0]["upstream"];
        assert_eq!(upstream["status"], "ok");
        assert_eq!(
            upstream["capabilities"],
            serde_json::json!(["prompts", "tools"])
        );
        assert_eq!(upstream["tools"][1]["original"], "a_very_long_name");
    }

    #[test]
    fn an_upstream_without_peer_info_has_no_announcement() {
        let report = report_with_upstream(UpstreamReport::Ok {
            protocol: None,
            server: None,
            capabilities: Vec::new(),
            tools: vec![ToolReport {
                name: "s__ping".into(),
                original: "ping".into(),
            }],
        });
        let text = text_of(&[report]);
        assert!(!text.contains("protocol"), "{text}");
        assert!(text.contains("✓ 1 tool\n"), "{text}");
    }

    #[test]
    fn an_announcement_without_server_or_capabilities() {
        let line = announcement("2025-06-18", &None, &[]);
        assert_eq!(line, "protocol 2025-06-18 · (none)");
    }

    #[test]
    fn a_failed_upstream_is_a_problem_in_both_formats() {
        let report = report_with_upstream(UpstreamReport::Error {
            reason: "boom".into(),
        });
        assert!(!report.is_ok());
        let text = text_of(std::slice::from_ref(&report));
        assert!(text.contains("✗ tools unavailable: boom"), "{text}");
        let json = json_of(&[report]);
        assert_eq!(
            json["servers"][0]["upstream"],
            serde_json::json!({"status": "error", "reason": "boom"})
        );
    }

    #[test]
    fn a_report_for_an_unknown_server_is_added_once() {
        let mut reports = Vec::new();
        report_for(&mut reports, "late").upstream =
            Some(UpstreamReport::Error { reason: "x".into() });
        report_for(&mut reports, "late");
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn summary_of_a_clean_config() {
        let reports = check_secrets(
            &Config::parse(r#"{"mcpServers": {}}"#).unwrap(),
            &MemoryStore::new(),
        );
        assert_eq!(summary(&reports, true), "0 servers, all ok");
    }
}
