use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use rmcp::ServiceExt;

use toolward::cli::{self, AuthCommand, Cli, Command, SecretCommand};
use toolward::config::Config;
use toolward::import;
use toolward::proxy::Proxy;
use toolward::store::{CachedStore, CredentialStore, KeyringStore, validate_user_account};

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    // `serve` must not hold stdout: it carries the MCP protocol.
    if matches!(cli.command, Command::Serve) {
        let config = Config::load(&cli.config_path()?)?;
        let store: Arc<dyn CredentialStore> = Arc::new(CachedStore::new(KeyringStore::native()?));
        return serve(&config, &store);
    }

    let mut out = io::stdout().lock();
    match &cli.command {
        Command::Secret(SecretCommand::Set { account }) => {
            // Fail before prompting, so the user does not type a secret for a rejected name.
            validate_user_account(account)?;
            let store = KeyringStore::native()?;
            let secret = cli::read_secret(account)?;
            cli::secret_set(&store, account, &secret, &mut out)?;
        }
        Command::Secret(SecretCommand::Delete { account }) => {
            let store = KeyringStore::native()?;
            cli::secret_delete(&store, account, &mut out)?;
        }
        Command::Auth(AuthCommand::Login { server }) => {
            let config = Config::load(&cli.config_path()?)?;
            let (url, oauth) = config.oauth_server(server).map_err(anyhow::Error::msg)?;
            let store: Arc<dyn CredentialStore> = Arc::new(KeyringStore::native()?);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let request = toolward::oauth::LoginRequest { server, url, oauth };
            let announce = |url: &str| {
                eprintln!("Opening your browser. If it does not open, visit:\n{url}");
            };
            runtime
                .block_on(toolward::oauth::login(
                    request,
                    store,
                    &announce,
                    toolward::oauth::LOGIN_TIMEOUT,
                ))
                .map_err(anyhow::Error::msg)?;
            writeln!(out, "logged in to {server:?}")?;
        }
        Command::Auth(AuthCommand::Logout { server }) => {
            let store = KeyringStore::native()?;
            if toolward::oauth::logout(&store, server).map_err(anyhow::Error::msg)? {
                writeln!(out, "logged out of {server:?}")?;
            } else {
                writeln!(out, "no login stored for {server:?}")?;
            }
        }
        Command::Import { file, apply } => {
            let source = std::fs::read_to_string(file)
                .with_context(|| format!("cannot read {}", file.display()))?;
            let mut plan = import::plan(&source)?;
            if *apply {
                let store = KeyringStore::native()?;
                import::apply(&mut plan, &store, &cli.config_path()?)?;
            }
            import::report(&plan, *apply, &mut out)?;
        }
        Command::Check { tools } => {
            let config = Config::load(&cli.config_path()?)?;
            let store = CachedStore::new(KeyringStore::native()?);
            let mut ok = cli::check(&config, &store, &mut out)?;
            if *tools {
                let store: Arc<dyn CredentialStore> = Arc::new(store);
                let proxy = Proxy::from_config(&config, &store);
                writeln!(out)?;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                ok &= runtime.block_on(cli::check_tools(&proxy, &mut out))?;
            }
            if !ok {
                out.flush()?;
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Serve => unreachable!("handled above"),
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// Resolves on SIGINT or SIGTERM (Ctrl-C only on non-Unix platforms).
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn serve(config: &Config, store: &Arc<dyn CredentialStore>) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let proxy = Proxy::from_config(config, store);
        let running = proxy.clone().serve(rmcp::transport::stdio()).await?;
        // Stop on stdin EOF (the agent exited) or on a termination signal, and
        // either way shut the upstream children down.
        let cancel = running.cancellation_token();
        let signalled = tokio::spawn(async move {
            wait_for_signal().await;
            cancel.cancel();
        });
        let outcome = running.waiting().await;
        signalled.abort();
        proxy.shutdown().await;
        outcome?;
        Ok(ExitCode::SUCCESS)
    });
    // tokio's stdin read is a blocking call that cannot be cancelled; dropping
    // the runtime would wait for it until the agent closes the pipe.
    runtime.shutdown_background();
    result
}
