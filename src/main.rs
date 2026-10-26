mod checks;
mod collect;
mod delivery;
mod machines;
mod report;
mod review;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

/// Security posture of the developer workstations: each machine reports its own state, the instance collects and
/// reviews the reports.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the checks on this machine, queues the report and sends every queued report to the collector.
    Report {
        /// URL the reports are POSTed to.
        #[arg(long, env = "POSTURE_COLLECTOR", required_unless_present = "print")]
        collector: Option<String>,
        /// Tang server the LUKS devices must be bound to.
        #[arg(long, env = "POSTURE_TANG_URL")]
        tang_url: String,
        /// Holds the token of this machine and the queue of the reports not sent yet.
        #[arg(long, env = "POSTURE_STATE", default_value = "/var/lib/optionfactory-posture")]
        state: PathBuf,
        /// Prints the report instead of queueing and sending it.
        #[arg(long)]
        print: bool,
    },
    /// Stores the reports POSTed through nginx under the name of the machine whose token they carry, and summarizes them
    /// after thirty days.
    Collect {
        /// Unix socket for nginx: whoever can reach its directory can write reports.
        #[arg(
            long,
            env = "POSTURE_LISTEN",
            default_value = "/run/optionfactory-posture/collect.sock"
        )]
        listen: PathBuf,
        /// One subdirectory of reports per machine.
        #[arg(
            long,
            env = "POSTURE_REPORTS",
            default_value = "/var/lib/optionfactory-posture/reports"
        )]
        reports: PathBuf,
        /// The machines allowed to send, read again at every report.
        #[arg(
            long,
            env = "POSTURE_MACHINES",
            default_value = "/etc/optionfactory-posture/machines"
        )]
        machines: PathBuf,
    },
    /// Prints this machine's name and the hash of its token, to compare with the pending machine before approving it.
    Id {
        #[arg(long, env = "POSTURE_STATE", default_value = "/var/lib/optionfactory-posture")]
        state: PathBuf,
    },
    /// Prints the machines waiting for approval, as entries for the list of machines.
    Pending {
        reports: PathBuf,
        #[arg(
            long,
            env = "POSTURE_MACHINES",
            default_value = "/etc/optionfactory-posture/machines"
        )]
        machines: PathBuf,
    },
    /// Prints one line per machine of the list that needs attention, and one per machine waiting for approval.
    Review {
        /// Directory with one subdirectory of reports per machine.
        reports: PathBuf,
        #[arg(
            long,
            env = "POSTURE_MACHINES",
            default_value = "/etc/optionfactory-posture/machines"
        )]
        machines: PathBuf,
    },
}

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Report {
            collector,
            tang_url,
            state,
            print,
        } => {
            let report = report::Report::take(&tang_url);
            match collector {
                Some(collector) if !print => delivery::queue_and_send(report, &state, &collector),
                _ => serde_json::to_string_pretty(&report)
                    .map(|json| println!("{json}"))
                    .map_err(|e| e.to_string()),
            }
        }
        Command::Collect {
            listen,
            reports,
            machines,
        } => collect::collect(listen, reports, machines),
        Command::Review { reports, machines } => {
            machines::read(&machines).and_then(|machines| review::review(&reports, &machines))
        }
        Command::Id { state } => machines::id(&state),
        Command::Pending { reports, machines } => {
            machines::read(&machines).map(|machines| machines::print_pending(&reports, &machines))
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("optionfactory-posture: {e}");
            ExitCode::FAILURE
        }
    }
}
