//! Private stdio control adapter. No TCP listener or local prover.
use serde::Deserialize;
use std::io::{Read, Write};
use trusted_shim::{
    contracts::ExecutionIdentity,
    docker::DockerDriver,
    runtime::{LaunchRequest, RuntimeDriver},
    Error, Result,
};

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Launch {
        request: Box<LaunchRequest>,
    },
    Inspect {
        execution: ExecutionIdentity,
    },
    Stop {
        execution: ExecutionIdentity,
    },
    Delete {
        execution: ExecutionIdentity,
    },
    Network {
        execution: ExecutionIdentity,
        config: trusted_shim::data_plane::NetworkConfig,
    },
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--probe-machine" {
        println!(
            "{}",
            serde_json::json!({
                "tee_interfaces": trusted_shim::machine::detect()?,
                "attestation_verified": false,
                "tee_runtime_ready": false,
            })
        );
        return Ok(());
    }
    if matches!(args.len(), 6 | 8)
        && args[1] == "--serve"
        && args[2] == "--state-dir"
        && args[4] == "--node-id"
    {
        let config = if args.len() == 8 {
            if args[6] != "--options" || args[7].len() > 128 * 1024 {
                return Err(Error::InvalidContract);
            }
            serde_json::from_str(&args[7]).map_err(|_| Error::InvalidContract)?
        } else {
            trusted_shim::daemon::DaemonConfig::default()
        };
        let stop = tokio_util::sync::CancellationToken::new();
        let signal = stop.clone();
        tokio::spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            signal.cancel();
        });
        return trusted_shim::daemon::serve_configured(
            std::path::Path::new(&args[3]),
            args[5].clone(),
            config,
            stop,
        )
        .await;
    }
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("{{\"protocol\":1,\"drivers\":[\"docker\"],\"features\":[\"data-plane-v1\",\"runtime-management-v1\",\"single-use-ingress-v1\",\"openshell-access-v1\"]}}");
        return Ok(());
    }
    if args.len() != 5 || args[1] != "--state-dir" || args[3] != "--node-id" {
        return Err(Error::InvalidContract);
    }
    let driver = DockerDriver::new(&args[2], args[4].clone())?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::InvalidContract);
    }
    let command: Command = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidContract)?;
    let response = match command {
        Command::Launch { request } => serde_json::to_value(driver.launch(&request).await?)
            .map_err(|_| Error::InvalidContract)?,
        Command::Inspect { execution } => serde_json::to_value(driver.inspect(&execution).await?)
            .map_err(|_| Error::InvalidContract)?,
        Command::Stop { execution } => {
            driver.stop(&execution).await?;
            serde_json::json!({"stopped":true})
        }
        Command::Delete { execution } => {
            driver.delete(&execution).await?;
            serde_json::json!({"cleaned":true})
        }
        Command::Network { execution, config } => {
            let stop = tokio_util::sync::CancellationToken::new();
            let signal = stop.clone();
            tokio::spawn(async move {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("signal");
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                signal.cancel();
            });
            trusted_shim::data_plane::serve(&driver, &execution, &config, stop).await?;
            serde_json::json!({"disconnected":true})
        }
    };
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &response).map_err(|_| Error::Unavailable)?;
    writeln!(output).map_err(|_| Error::Unavailable)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
