use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use toolward::cli::{self, Cli, Command, SecretCommand};
use toolward::config::Config;
use toolward::store::{KeyringStore, validate_account};

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
        Command::Check => {
            let config = Config::load(&cli.config_path()?)?;
            let store = KeyringStore::native()?;
            if !cli::check(&config, &store, &mut out)? {
                out.flush()?;
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}
