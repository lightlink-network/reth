use clap::Parser;
use reth_cli_runner::CliRunner;

mod command;
mod database_downloader;

use command::UnwindDiffCommand;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable backtraces unless explicitly disabled
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = CliRunner::try_default_runtime()?.run_command_until_exit(|ctx| {
        let command = UnwindDiffCommand::parse();
        command.execute(ctx)
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
    Ok(())
}

