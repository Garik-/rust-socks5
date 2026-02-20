use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::config::SocksConfig;

use super::ProtocolError;
use super::cancellable_io;
use super::protocol::{self, IoTimeouts, Reply, SocksSession};

pub async fn handle_connection(
    mut src: TcpStream,
    shutdown: CancellationToken,
    config: SocksConfig,
) -> Result<(), ProtocolError> {
    let started_at = Instant::now();
    let io_timeouts = IoTimeouts {
        read: config.read_timeout,
        write: config.write_timeout,
    };
    let session = SocksSession::new(&shutdown, io_timeouts);

    let result = async {
        session.handshake(&mut src).await?;
        configure_stream(&src)?;

        let addr = match session.request(&mut src).await {
            Ok(addr) => addr,
            Err(ProtocolError::AddressTypeNotSupported) => {
                session
                    .send_fail(&mut src, Reply::AddressTypeNotSupported)
                    .await?;
                return Ok(());
            }
            Err(ProtocolError::CommandNotSupported) => {
                session
                    .send_fail(&mut src, Reply::CommandNotSupported)
                    .await?;
                return Ok(());
            }
            Err(err) => return Err(err),
        };

        debug!(addr = %addr, "request");

        let mut dst = match connect_target(addr, &shutdown, config.connect_timeout).await {
            Ok(stream) => stream,
            Err(err) => {
                session.send_fail(&mut src, map_connect_error(&err)).await?;
                return Ok(());
            }
        };
        configure_stream(&dst)?;

        debug!("connected");

        let reply = protocol::succeeded_reply(dst.local_addr()?);
        session.write_all(&mut src, &reply).await?;

        let (from_client, from_target) = relay_bidirectional(&mut src, &mut dst, &shutdown).await?;
        debug!(
            from_client,
            from_target,
            elapsed_ms = started_at.elapsed().as_millis(),
            "client closed connection"
        );

        Ok(())
    }
    .await;

    match result {
        Err(ProtocolError::Io(ref err)) if err.kind() == io::ErrorKind::Interrupted => {
            debug!("connection received shutdown signal");
            Ok(())
        }
        other => other,
    }
}

#[inline]
fn map_connect_error(e: &io::Error) -> Reply {
    use io::ErrorKind::*;

    match e.kind() {
        ConnectionRefused => Reply::ConnectionRefused,
        NetworkUnreachable => Reply::NetworkUnreachable,
        HostUnreachable => Reply::HostUnreachable,
        TimedOut => Reply::HostUnreachable,
        PermissionDenied => Reply::ConnectionNotAllowedByRuleset,
        _ => Reply::ServerFailure,
    }
}

async fn connect_target(
    addr: SocketAddr,
    shutdown: &CancellationToken,
    connect_timeout: std::time::Duration,
) -> Result<TcpStream, io::Error> {
    cancellable_io(shutdown, async move {
        match time::timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
        }
    })
    .await
}

async fn relay_bidirectional(
    src: &mut TcpStream,
    dst: &mut TcpStream,
    shutdown: &CancellationToken,
) -> Result<(u64, u64), io::Error> {
    cancellable_io(shutdown, async { copy_bidirectional(src, dst).await }).await
}

#[inline]
fn configure_stream(stream: &TcpStream) -> Result<(), io::Error> {
    stream.set_nodelay(true)?;
    Ok(())
}
