use std::convert::TryFrom;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const VERSION: u8 = 0x05;

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub(super) enum Reply {
    Succeeded = 0,
    ServerFailure = 1,
    ConnectionNotAllowedByRuleset = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum AddressType {
    IPv4 = 0x01,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddressType::IPv4),
            0x04 => Ok(AddressType::IPv6),
            _ => Err(()),
        }
    }
}

struct ServerReply {
    rep: Reply,
    atyp: AddressType,
    addr: Vec<u8>,
    port: u16,
}

impl ServerReply {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.push(VERSION);
        buf.push(self.rep as u8);
        buf.push(0);
        buf.push(self.atyp as u8);
        buf.extend_from_slice(&self.addr);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    fn succeeded(local: SocketAddr) -> Self {
        use std::net::IpAddr::*;

        let (atyp, addr) = match local.ip() {
            V4(v4) => (AddressType::IPv4, v4.octets().to_vec()),
            V6(v6) => (AddressType::IPv6, v6.octets().to_vec()),
        };

        Self {
            rep: Reply::Succeeded,
            atyp,
            addr,
            port: local.port(),
        }
    }

    fn fail(rep: Reply) -> Self {
        Self {
            rep,
            atyp: AddressType::IPv4,
            addr: vec![0, 0, 0, 0],
            port: 0,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ProtocolError {
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("command not supported")]
    CommandNotSupported,
    #[error("address type not supported")]
    AddressTypeNotSupported,
    #[error("no acceptable methods")]
    NoAcceptableMethods,
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct IoTimeouts {
    pub(super) read: Duration,
    pub(super) write: Duration,
}

pub(super) struct SocksSession<'a> {
    shutdown: &'a CancellationToken,
    timeouts: IoTimeouts,
}

impl<'a> SocksSession<'a> {
    pub(super) fn new(shutdown: &'a CancellationToken, timeouts: IoTimeouts) -> Self {
        Self { shutdown, timeouts }
    }

    pub(super) async fn handshake<S>(&self, stream: &mut S) -> Result<(), ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
        const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

        let mut header = [0u8; 2];
        self.read_exact(stream, &mut header).await?;

        if header[0] != VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }

        let n_methods = header[1] as usize;
        if !(1..=255).contains(&n_methods) {
            return Err(ProtocolError::UnexpectedEof);
        }

        let mut methods = vec![0u8; n_methods];
        self.read_exact(stream, &mut methods).await?;

        header[1] = NO_ACCEPTABLE_METHODS;
        for method in &methods {
            if *method == NO_AUTHENTICATION_REQUIRED {
                header[1] = NO_AUTHENTICATION_REQUIRED;
                break;
            }
        }

        self.write_all(stream, &header).await?;

        if header[1] == NO_ACCEPTABLE_METHODS {
            return Err(ProtocolError::NoAcceptableMethods);
        }

        Ok(())
    }

    pub(super) async fn request<S>(&self, stream: &mut S) -> Result<SocketAddr, ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        const CMD_CONNECT: u8 = 0x01;

        let mut header = [0u8; 4];
        self.read_exact(stream, &mut header).await?;

        if header[0] != VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }

        if header[1] != CMD_CONNECT {
            return Err(ProtocolError::CommandNotSupported);
        }

        if header[2] != 0x00 {
            return Err(ProtocolError::UnexpectedEof);
        }

        let atyp =
            AddressType::try_from(header[3]).map_err(|_| ProtocolError::AddressTypeNotSupported)?;

        match atyp {
            AddressType::IPv4 => self.read_ipv4(stream).await,
            AddressType::IPv6 => self.read_ipv6(stream).await,
        }
    }

    pub(super) async fn send_fail<S>(&self, stream: &mut S, reply: Reply) -> Result<(), io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let reply = ServerReply::fail(reply);
        self.write_all(stream, &reply.to_bytes()).await
    }

    pub(super) async fn write_all<S>(&self, stream: &mut S, buf: &[u8]) -> Result<(), io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::select! {
            _ = self.shutdown.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown")),
            result = timeout(self.timeouts.write, stream.write_all(buf)) => {
                match result {
                    Ok(inner) => inner,
                    Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "write timeout")),
                }
            }
        }
    }

    async fn read_ipv4<S>(&self, stream: &mut S) -> Result<SocketAddr, ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut ip_bytes = [0u8; 4];
        self.read_exact(stream, &mut ip_bytes).await?;

        let mut port_bytes = [0u8; 2];
        self.read_exact(stream, &mut port_bytes).await?;

        Ok(SocketAddr::from((
            Ipv4Addr::from(ip_bytes),
            u16::from_be_bytes(port_bytes),
        )))
    }

    async fn read_ipv6<S>(&self, stream: &mut S) -> Result<SocketAddr, ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut ip_bytes = [0u8; 16];
        self.read_exact(stream, &mut ip_bytes).await?;

        let mut port_bytes = [0u8; 2];
        self.read_exact(stream, &mut port_bytes).await?;

        Ok(SocketAddr::from((
            Ipv6Addr::from(ip_bytes),
            u16::from_be_bytes(port_bytes),
        )))
    }

    async fn read_exact<S>(&self, stream: &mut S, buf: &mut [u8]) -> Result<(), io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::select! {
            _ = self.shutdown.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown")),
            result = timeout(self.timeouts.read, stream.read_exact(buf)) => {
                match result {
                    Ok(inner) => inner.map(|_| ()),
                    Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
                }
            }
        }
    }
}

pub(super) fn succeeded_reply(local: SocketAddr) -> Vec<u8> {
    ServerReply::succeeded(local).to_bytes()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio_util::sync::CancellationToken;

    use std::time::Duration;

    use super::{IoTimeouts, ProtocolError, SocksSession};

    const TEST_TIMEOUTS: IoTimeouts = IoTimeouts {
        read: Duration::from_secs(1),
        write: Duration::from_secs(1),
    };

    #[tokio::test]
    async fn handshake_accepts_no_auth_method() {
        let (mut client, mut server) = duplex(64);
        let shutdown = CancellationToken::new();

        let server_task = tokio::spawn(async move {
            let session = SocksSession::new(&shutdown, TEST_TIMEOUTS);
            session.handshake(&mut server).await
        });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(response, [0x05, 0x00]);
        assert!(server_task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn request_parses_ipv4_connect() {
        let (mut client, mut server) = duplex(64);
        let shutdown = CancellationToken::new();

        let server_task = tokio::spawn(async move {
            let session = SocksSession::new(&shutdown, TEST_TIMEOUTS);
            session.request(&mut server).await
        });

        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
            .await
            .unwrap();

        let parsed = server_task.await.unwrap().unwrap();
        assert_eq!(
            parsed,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
        );
    }

    #[tokio::test]
    async fn request_rejects_unsupported_address_type() {
        let (mut client, mut server) = duplex(64);
        let shutdown = CancellationToken::new();

        let server_task = tokio::spawn(async move {
            let session = SocksSession::new(&shutdown, TEST_TIMEOUTS);
            session.request(&mut server).await
        });

        client.write_all(&[0x05, 0x01, 0x00, 0x03]).await.unwrap();

        let err = server_task.await.unwrap().unwrap_err();
        assert!(matches!(err, ProtocolError::AddressTypeNotSupported));
    }
}
