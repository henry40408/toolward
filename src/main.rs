use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rmcp::ServiceExt;

use toolward::cli::{self, Cli, Command, SecretCommand};
use toolward::config::Config;
use toolward::proxy::Proxy;
use toolward::store::{CredentialStore, KeyringStore, validate_account};

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
        let store: Arc<dyn CredentialStore> = Arc::new(KeyringStore::native()?);
        return serve(&config, &store);
    }

    let mut out = io::stdout().lock();
    match &cli.command {
        Command::Secret(SecretCommand::Set { account }) => {
            validate_account(account)?;
            let store = KeyringStore::native()?;
            let secret = cli::read_secret(account)?;
            cli::secret_set(&store, account, &secret, &mut out)?;
        }
        Command::Secret(SecretCommand::Delete { account }) => {
            let store = KeyringStore::native()?;
            cli::secret_delete(&store, account, &mut out)?;
        }
        Command::Check { tools } => {
            let config = Config::load(&cli.config_path()?)?;
            let store = KeyringStore::native()?;
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
