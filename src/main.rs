use std::io;

use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, warn};
use tracing_subscriber::FmtSubscriber;

mod config;
mod socks;
use config::AppConfig;
use socks::handle_connection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::from_env()?;

    let subscriber = FmtSubscriber::builder()
        .with_max_level(config.log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!(
        listen_addr = %config.listen_addr,
        shutdown_timeout_secs = config.shutdown_timeout.as_secs(),
        connect_timeout_secs = config.socks.connect_timeout.as_secs(),
        read_timeout_secs = config.socks.read_timeout.as_secs(),
        write_timeout_secs = config.socks.write_timeout.as_secs(),
        log_level = %config.log_level,
        "configuration loaded"
    );

    let listener = TcpListener::bind(&config.listen_addr).await?;
    info!(addr = %config.listen_addr, "server listening");

    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            signal = shutdown_signal() => {
                if let Err(err) = signal {
                    error!(error = %err, "failed to listen for shutdown signal");
                } else {
                    info!("shutdown signal received");
                }
                shutdown.cancel();
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((socket, peer_addr)) => {
                        debug!(client = %peer_addr, "accepted connection");
                        let task_shutdown = shutdown.clone();
                        let socks_config = config.socks.clone();
                        let span = info_span!("connection", client = %peer_addr);
                        tasks.spawn(
                            async move {
                                if let Err(err) = handle_connection(socket, task_shutdown, socks_config).await {
                                    error!(error = %err, "connection failed");
                                } else {
                                    debug!("connection completed successfully");
                                }
                            }
                            .instrument(span),
                        );
                    }
                    Err(err) => {
                        error!(error = %err, "accept failed");
                    }
                }
            }
        }
    }

    let graceful = async { while tasks.join_next().await.is_some() {} };

    match time::timeout(config.shutdown_timeout, graceful).await {
        Ok(()) => info!("graceful shutdown completed"),
        Err(_) => {
            warn!("graceful shutdown timeout reached, aborting active tasks");
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<(), io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = sigterm.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<(), io::Error> {
    tokio::signal::ctrl_c().await
}
