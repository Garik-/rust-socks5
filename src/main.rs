use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

const VERSION: u8 = 0x05;

const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

#[derive(Debug, PartialEq)]
enum ProtocolError {
    UnsupportedVersion,
    UnexpectedEof,
    UnsupportedMethod,
}

fn handshake(buf: &[u8]) -> Result<u8, ProtocolError> {
    if buf.is_empty() || buf.len() < 3 {
        return Err(ProtocolError::UnexpectedEof);
    }

    if buf[0] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }

    let n_methods = buf[1] as usize;
    if n_methods > buf.len() - 2 {
        return Err(ProtocolError::UnexpectedEof);
    }

    // print_hex(&buf[2..2 + n_methods]);

    for method in &buf[2..2 + n_methods] {
        if *method == NO_AUTHENTICATION_REQUIRED {
            return Ok(NO_AUTHENTICATION_REQUIRED);
        }
    }

    return Ok(NO_ACCEPTABLE_METHODS);
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

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0u8; 1024];

    let n = stream
        .read(&mut buffer)
        .expect("failed to read from stream");

    print_hex(&buffer[..n]);

    let method = match handshake(&buffer[..n]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed handshake: {:?}", e);
            return;
        }
    };

    buffer[1] = method;

    print_hex(&buffer[..2]);

    stream
        .write(&buffer[..2])
        .expect("failed to write handshake");
    stream.flush().expect("failed to flush stream");

    if method == NO_ACCEPTABLE_METHODS {
        return;
    }

    let n = stream
        .read(&mut buffer)
        .expect("failed to read from stream");

    print_hex(&buffer[..n]);
}

fn main() {
    const ADDR: &str = "127.0.0.1:7878";
    let listener = TcpListener::bind(ADDR).expect("trololo");
    println!("server listening on {}", ADDR);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    handle_connection(stream);
                });
            }
            Err(e) => {
                eprintln!("connection failed: {}", e);
            }
        }
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_handshake_empty_buffer() {
        let buf: [u8; 0] = [];
        let result = handshake(&buf);
        assert_eq!(result, Err(ProtocolError::UnexpectedEof));
    }

    #[test]
    fn test_handshake_short_buffer() {
        let buf = [5, 1];
        let result = handshake(&buf);
        assert_eq!(result, Err(ProtocolError::UnexpectedEof));
    }

    #[test]
    fn test_handskake_wrong_version() {
        let buf = [4, 2, 0];
        let result = handshake(&buf);
        assert_eq!(result, Err(ProtocolError::UnsupportedVersion));
    }

    #[test]
    fn test_handshake_ok() {
        let buf = [5, 2, 0, 1];
        let result = handshake(&buf);
        assert_eq!(result, Ok(()));
    }
}
