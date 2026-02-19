use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, subscriber};
use tracing_subscriber::FmtSubscriber;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

const VERSION: u8 = 0x05;

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum Reply {
    Succeeded = 0,
    ServerFailure = 1,
    ConnectionNotAllowedByRuleset = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TTLExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum AddressType {
    IPv4 = 0x01,
    // Domain = 0x03,
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
        buf.push(0); // RSV
        buf.push(self.atyp as u8);

        buf.extend_from_slice(&self.addr);
        buf.extend_from_slice(&self.port.to_be_bytes());

        buf
    }

    fn succeeded(local: SocketAddr) -> Self {
        let (atyp, addr) = match local.ip() {
            std::net::IpAddr::V4(v4) => (AddressType::IPv4, v4.octets().to_vec()),
            std::net::IpAddr::V6(v6) => (AddressType::IPv6, v6.octets().to_vec()),
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
enum ProtocolError {
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("command not supported")]
    CommandNotSupported,

    #[error("address type not supported")]
    AddressTypeNotSupported,

    #[error("unexpected eof")]
    UnexpectedEof,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

fn print_hex(buf: &[u8]) {
    for (i, chunk) in buf.chunks(16).enumerate() {
        print!("{:08X}: ", i * 16);

        for b in chunk {
            print!("{:02X} ", b);
        }

        println!();
    }
}

fn handshake(stream: &mut (impl Read + Write)) -> Result<(), ProtocolError> {
    const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
    const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

    let mut header = [0u8; 2];

    stream.read_exact(&mut header)?;
    print_hex(&header);

    if header[0] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }

    let n_methods = header[1] as usize;

    if n_methods < 1 || n_methods > 255 {
        return Err(ProtocolError::UnexpectedEof);
    }

    let mut methods = vec![0u8; n_methods];

    stream.read_exact(&mut methods)?;
    print_hex(&methods);

    header[1] = NO_ACCEPTABLE_METHODS;

    for method in &methods {
        if *method == NO_AUTHENTICATION_REQUIRED {
            header[1] = NO_AUTHENTICATION_REQUIRED;
            break;
        }
    }

    print_hex(&header);

    stream.write_all(&header)?;
    stream.flush()?;

    Ok(())
}

fn send_fail(stream: &mut impl Write, reply: Reply) -> Result<(), ProtocolError> {
    let reply = ServerReply::fail(reply);
    stream.write_all(&reply.to_bytes())?;
    stream.flush()?;

    Ok(())
}

fn read_ipv4(stream: &mut impl Read) -> Result<SocketAddr, ProtocolError> {
    let mut ip_bytes = [0u8; 4];
    stream.read_exact(&mut ip_bytes)?;

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes)?;

    let addr = SocketAddr::from((Ipv4Addr::from(ip_bytes), u16::from_be_bytes(port_bytes)));

    Ok(addr)
}

fn read_ipv6(stream: &mut impl Read) -> Result<SocketAddr, ProtocolError> {
    let mut ip_bytes = [0u8; 16];
    stream.read_exact(&mut ip_bytes)?;

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes)?;

    let addr = SocketAddr::from((Ipv6Addr::from(ip_bytes), u16::from_be_bytes(port_bytes)));

    Ok(addr)
}

fn request(stream: &mut (impl Read + Write)) -> Result<SocketAddr, ProtocolError> {
    const CMD_CONNECT: u8 = 0x01;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;

    print_hex(&header);

    if header[0] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }

    if header[1] != CMD_CONNECT {
        return Err(ProtocolError::CommandNotSupported);
    }

    let atyp =
        AddressType::try_from(header[3]).map_err(|_| ProtocolError::AddressTypeNotSupported)?;

    match atyp {
        AddressType::IPv4 => return read_ipv4(stream),
        AddressType::IPv6 => return read_ipv6(stream),
    };
}

fn handle_connection(mut stream: TcpStream) -> Result<(), ProtocolError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    handshake(&mut stream)?;

    let addr = match request(&mut stream) {
        Ok(addr) => addr,
        Err(ProtocolError::AddressTypeNotSupported) => {
            return send_fail(&mut stream, Reply::AddressTypeNotSupported);
        }
        Err(ProtocolError::CommandNotSupported) => {
            return send_fail(&mut stream, Reply::CommandNotSupported);
        }
        Err(e) => return Err(e),
    };

    debug!(addr = %addr, "request");

    Ok(())
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    const ADDR: &str = "127.0.0.1:7878";
    let listener = TcpListener::bind(ADDR).expect("trololo");
    info!(addr = %ADDR, "server listening");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    if let Err(e) = handle_connection(stream) {
                        error!(error = %e, "handle_connection");
                    }
                    debug!("connection close");
                });
            }
            Err(e) => {
                error!(error = %e, "connection failed");
            }
        }
    }
}
