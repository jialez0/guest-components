// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::AttestationAgent;
use clap::{arg, command, Parser};
use const_format::concatcp;
use log::{debug, info};
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::signal::unix::{signal, SignalKind};
use ttrpc::asynchronous::{Server, Service};
use ttrpc_dep::server::AA;

use crate::ttrpc_dep::ttrpc_protocol::attestation_agent_ttrpc::create_attestation_agent_service;

mod ttrpc_dep;

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers/attestation-agent/";
const UNIX_SOCKET_PREFIX: &str = "unix://";
const DEFAULT_ATTESTATION_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    DEFAULT_UNIX_SOCKET_DIR,
    "attestation-agent.sock"
);

const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version"));

#[derive(Debug, Parser)]
#[command(author, version = Some(VERSION))]
struct Cli {
    /// Attestation ttRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation ttRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock unix:///tmp/attestation`
    #[arg(default_value_t = DEFAULT_ATTESTATION_SOCKET_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,

    /// Configuration file for Attestation Agent
    ///
    /// Example:
    /// `--config /etc/attestation-agent.conf`
    #[arg(short, long)]
    config_file: Option<String>,
}

pub fn start_ttrpc_service(aa: AttestationAgent) -> Result<HashMap<String, Service>> {
    let service = AA { inner: aa };
    let service = Arc::new(service);
    let get_resource_service = create_attestation_agent_service(service);
    Ok(get_resource_service)
}

#[tokio::main]
pub async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    if !Path::new(DEFAULT_UNIX_SOCKET_DIR).exists() {
        std::fs::create_dir_all(DEFAULT_UNIX_SOCKET_DIR).expect("Create unix socket dir failed");
    }

    clean_previous_sock_file(&cli.attestation_sock)
        .context("clean previous attestation socket file")?;

    let mut aa = AttestationAgent::new(cli.config_file.as_deref()).context("start AA")?;
    aa.init().await.context("init AA")?;

    // Check if heartbeat is enabled and get interval
    let config = aa.config.read().await;
    let _heartbeat_enabled = config.aa_instance.heartbeat.enabled;
    let _heartbeat_interval = config.aa_instance.heartbeat.interval_minutes.unwrap_or(5); // Default 5 minutes
    drop(config);

    let att = start_ttrpc_service(aa)?;

    let mut atts = Server::new()
        .bind(&cli.attestation_sock)
        .context("cannot bind attestation ttrpc service")?
        .register_service(att);

    atts.start().await?;
    debug!(
        "Attestation ttRPC service listening on: {:?}",
        cli.attestation_sock
    );

    // Start heartbeat task if enabled
    #[cfg(feature = "instance_info")]
    let heartbeat_task = if _heartbeat_enabled {
        let config_file = cli.config_file.clone();
        Some(tokio::spawn(async move {
            use attestation_agent::instance_info::InstanceHeartbeat;
            use log::warn;
            use tokio::time::{interval, Duration};
            let heartbeat = match InstanceHeartbeat::new_from_config_path(config_file.as_deref()) {
                Result::Ok(h) => h,
                Result::Err(e) => {
                    warn!("Failed to create heartbeat instance: {}", e);
                    return;
                }
            };

            let mut timer = interval(Duration::from_secs(_heartbeat_interval * 60)); // Convert minutes to seconds
            loop {
                timer.tick().await;
                if let Err(e) = heartbeat.send_heartbeat().await {
                    warn!("Heartbeat failed: {}", e);
                } else {
                    debug!("Heartbeat sent successfully");
                }
            }
        }))
    } else {
        None
    };

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => {
            info!("Client terminal disconnected.");
            atts.shutdown().await?;
        }
        _ = interrupt.recv() => {
            info!("SIGINT received, gracefully shutdown.");
            atts.shutdown().await?;
        }
    };

    // Cancel heartbeat task if it was started
    #[cfg(feature = "instance_info")]
    if let Some(task) = heartbeat_task {
        task.abort();
    }

    Ok(())
}

fn clean_previous_sock_file(unix_socket: &str) -> Result<()> {
    let path = unix_socket
        .strip_prefix(UNIX_SOCKET_PREFIX)
        .ok_or_else(|| anyhow!("socket address scheme is not expected"))?;

    if Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }

    Ok(())
}
