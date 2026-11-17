//! Explicit, non-destructive local backup CLI. Secrets are never arguments/output.
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "quicksave",
    version,
    about = "Encrypted local backups for your own computer",
    long_about = "QuickSave development preview. Local encrypted folder snapshots with explicit recovery keys. No SSH, remote machine, cloud deletion, automatic retention, or existing Noland repository access. Restore currently requires an empty destination. Close applications before capture; this is not an application-atomic snapshot."
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report implemented native capabilities and explicit limitations.
    Capabilities,
    /// Show platform-specific QuickSave locations without creating them.
    Directories,
    /// Read-only discovery; discovered applications are not automatically authorized.
    Discover,
    /// Initialize an empty local repository and save a NEW external recovery-key file.
    Init {
        #[arg(long)]
        repository: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Capture a folder into an additive encrypted snapshot. Source stays untouched.
    Backup {
        #[arg(long)]
        repository: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Authenticate and list immutable snapshot history.
    List {
        #[arg(long)]
        repository: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Restore an authenticated snapshot into an existing EMPTY approved folder.
    Restore {
        #[arg(long)]
        repository: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
}

fn run(arguments: Arguments) -> Result<serde_json::Value> {
    match arguments.command {
        Command::Capabilities => Ok(serde_json::json!({
            "platform": quicksave_platform::capabilities(),
            "integrations": quicksave_integrations::integration_capabilities(),
            "engineLimits": quicksave_client::engine_limits(),
            "product": "QuickSave",
            "releaseStage": "development-preview",
            "nolandRepositoryCompatibility": false,
            "restoreOverwrites": false,
            "backgroundService": false,
            "automaticRetention": false
        })),
        Command::Directories => quicksave_platform::app_directories(),
        Command::Discover => quicksave_integrations::discover_applications(),
        Command::Init {
            repository,
            key_file,
        } => quicksave_client::initialize_repository(&repository, &key_file),
        Command::Backup {
            repository,
            source,
            key_file,
        } => quicksave_client::backup_folder(&repository, &source, &key_file),
        Command::List {
            repository,
            key_file,
        } => quicksave_client::list_snapshots(&repository, &key_file),
        Command::Restore {
            repository,
            snapshot,
            destination,
            key_file,
        } => quicksave_client::restore_snapshot(&repository, &snapshot, &destination, &key_file),
    }
}

fn main() -> std::process::ExitCode {
    let arguments = Arguments::parse();
    match run(arguments) {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).expect("JSON value serializes")
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("QuickSave: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
