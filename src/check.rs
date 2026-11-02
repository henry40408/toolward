//! The report `toolward check` prints: one block per server.
//!
//! The checks collect their findings first and `render` prints them last,
//! so a server's secrets and its tools appear together.

use std::io::{self, Write};

use rmcp::model::{ServerCapabilities, ServerPeerInfo};
use serde_json::Value;

use crate::config::Config;
use crate::names::SEPARATOR;
use crate::oauth;
use crate::proxy::Proxy;
use crate::store::CredentialStore;
use crate::upstream::Upstream;

/// One line of the report: what was checked and how it went.
pub struct Finding {
    pub ok: bool,
    pub text: String,
    /// A command that solves the problem.
    pub fix: Option<String>,
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

pub struct ServerReport {
    pub name: String,
    pub findings: Vec<Finding>,
    /// The tool names the agent will see. Empty until `check_tools` ran.
    pub tools: Vec<String>,
}

impl ServerReport {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            findings: Vec::new(),
            tools: Vec::new(),
        }
    }

    fn is_ok(&self) -> bool {
        self.findings.iter().all(|finding| finding.ok)
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
        if accounts.is_empty() {
            report.findings.push(Finding::ok("no secret references"));
        }
        if config.oauth_servers().any(|name| name == server) {
            report.findings.push(oauth_finding(store, server));
        }
        for account in &accounts {
            report.findings.push(secret_finding(store, account));
        }
        reports.push(report);
    }
    reports
}

fn oauth_finding(store: &dyn CredentialStore, server: &str) -> Finding {
    match oauth::is_logged_in(store, server) {
        Ok(true) => Finding::ok("oauth logged in"),
        Ok(false) => Finding::problem(
            "oauth not logged in",
            Some(format!("toolward auth login {server}")),
        ),
        Err(err) => Finding::problem(format!("oauth error: {err}"), None),
    }
}

fn secret_finding(store: &dyn CredentialStore, account: &str) -> Finding {
    match store.get(account) {
        Ok(Some(_)) => Finding::ok(account),
        Ok(None) => Finding::problem(
            format!("{account} missing"),
            Some(format!("toolward secret set {account}")),
        ),
        Err(err) => Finding::problem(format!("{account} error: {err}"), None),
    }
}

/// Connects to every upstream and adds what it announced (protocol version,
/// server, capabilities) and the tool names the agent will see, marking those
/// that were renamed.
pub async fn check_tools(proxy: &Proxy, reports: &mut Vec<ServerReport>) {
    for upstream in proxy.upstreams() {
        let report = report_for(reports, upstream.name());
        match upstream.tools().await {
            Ok(_) => {
                if let Some(info) = upstream.list_peer().await.ok().and_then(|p| p.peer_info()) {
                    let announced = upstream.redact(&describe_server(&info));
                    report.findings.push(Finding::ok(announced));
                }
                report.tools = tool_lines(upstream);
                report.findings.push(Finding::ok(format!(
                    "{} {}",
                    report.tools.len(),
                    plural(report.tools.len(), "tool", "tools")
                )));
            }
            Err(reason) => report.findings.push(Finding::problem(
                format!("tools unavailable: {}", upstream.redact(&reason)),
                None,
            )),
        }
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

fn tool_lines(upstream: &Upstream) -> Vec<String> {
    let name = upstream.name();
    upstream
        .tool_names()
        .into_iter()
        .map(|(exposed, original)| {
            let full = format!("{name}{SEPARATOR}{exposed}");
            if exposed == original {
                full
            } else {
                format!("{full}  (renamed from {original:?})")
            }
        })
        .collect()
}

/// What a server announced, on one line.
fn describe_server(info: &ServerPeerInfo) -> String {
    let mut parts = vec![format!("protocol {}", info.protocol_version)];
    if let Some(server) = &info.server_info {
        let text = format!("{} {}", server.name, server.version);
        // Server text must not start a line of its own.
        parts.push(text.replace(char::is_control, "?"));
    }
    parts.push(capability_names(&info.capabilities));
    parts.join(" · ")
}

/// The capabilities and extensions a server declares, such as `tools` or
/// `io.modelcontextprotocol/tasks`, sorted by name.
fn capability_names(capabilities: &ServerCapabilities) -> String {
    let Ok(Value::Object(fields)) = serde_json::to_value(capabilities) else {
        return "(unreadable)".into();
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
    if names.is_empty() {
        return "(none)".into();
    }
    names.join(", ")
}

/// Prints one block per server and a summary line.
/// `tools_checked` tells whether `check_tools` ran.
pub fn render(
    reports: &[ServerReport],
    tools_checked: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    for report in reports {
        writeln!(out, "{}", report.name)?;
        for finding in &report.findings {
            let mark = if finding.ok { "✓" } else { "✗" };
            writeln!(out, "  {mark} {}", finding.text)?;
            if let Some(fix) = &finding.fix {
                writeln!(out, "      fix: {fix}")?;
            }
        }
        for tool in &report.tools {
            writeln!(out, "      {tool}")?;
        }
        writeln!(out)?;
    }
    writeln!(out, "{}", summary(reports, tools_checked))
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
    use crate::store::MemoryStore;

    const CONFIG: &str = r#"{"mcpServers": {
        "a": {"command": "x", "env": {"T": "${keychain:present}"}},
        "b": {"command": "y", "env": {"T": "${keychain:absent}"}},
        "c": {"command": "z"}
    }}"#;

    fn rendered(tools_checked: bool) -> (bool, String) {
        let store = MemoryStore::with(&[("present", "TOPSECRET")]);
        let reports = check_secrets(&Config::parse(CONFIG).unwrap(), &store);
        let mut out = Vec::new();
        render(&reports, tools_checked, &mut out).unwrap();
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
            "io.modelcontextprotocol/tasks, prompts, tools"
        );
        assert_eq!(capability_names(&ServerCapabilities::default()), "(none)");
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
    fn summary_of_a_clean_config() {
        let reports = check_secrets(
            &Config::parse(r#"{"mcpServers": {}}"#).unwrap(),
            &MemoryStore::new(),
        );
        assert_eq!(summary(&reports, true), "0 servers, all ok");
    }
}
