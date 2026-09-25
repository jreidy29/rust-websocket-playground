use base64::{Engine, engine::general_purpose::STANDARD};
use sha1::{Digest, Sha1};
use std::io::{Error, ErrorKind};
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DELIM: &[u8] = b"\r\n\r\n";
const MAGIC_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const FIN_BIT: u8 = 0b1000_0000;
const OPCODE_MASK: u8 = 0b0000_1111;
const MASK_BIT: u8 = 0b1000_0000;
const LENGTH_MASK: u8 = 0b0111_1111;

#[derive(Debug, Default)]
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

fn compute_accept_key(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(MAGIC_GUID);
    let hash = hasher.finalize();
    STANDARD.encode(hash)
}

fn extract_websocket_key(request: &str) -> Option<String> {
    for line in request.lines() {
        if line.starts_with("Sec-WebSocket-Key:") {
            let Some((_, value)) = line.split_once(":") else {
                todo!();
            };
            return Some(value.trim().to_string());
        }
    }
    None
}

async fn process_headers(socket: &mut TcpStream) -> io::Result<String> {
    let mut char_buf = [0u8; 1];
    let mut first_buf = [0u8; 4];
    // read first 4 bytes in to header_buf if we don't have at least 4 bytes we can safely error
    socket.read_exact(&mut first_buf).await?;
    let mut header_buf: Vec<u8> = vec![];
    if first_buf != DELIM {
        header_buf.extend(&first_buf);
        loop {
            socket.read_exact(&mut char_buf).await?;
            header_buf.extend(&char_buf);
            char_buf = [0u8; 1];
            if &header_buf[header_buf.len() - 4..] == DELIM {
                break;
            }
        }
        return Ok(String::from_utf8(header_buf).unwrap());
    }
    Err(Error::new(ErrorKind::InvalidData, "Request was malformed"))
}

async fn send_handshake_response(socket: &mut TcpStream, accept_key: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key
    );
    println!("response: {}", response);
    socket.write_all(response.as_bytes()).await
}

async fn read_frame(socket: &mut TcpStream) -> io::Result<Frame> {
    // frame header parse
    let mut frame_header = [0u8; 2];
    socket.read_exact(&mut frame_header).await?;
    let mut frame = Frame {
        fin: frame_header[0] & FIN_BIT != 0,
        opcode: frame_header[0] & OPCODE_MASK,
        payload: vec![],
    };
    let mask_flag: bool = frame_header[1] & MASK_BIT != 0;
    // unmasking
    let mut mask = [0u8; 4];
    if mask_flag {
        socket.read_exact(&mut mask).await?;
    }

    // content length
    let u8_length = frame_header[1] & LENGTH_MASK;
    let payload_size: usize = if u8_length == 126 {
        let mut u16_bit_buf = [0u8; 2];
        socket.read_exact(&mut u16_bit_buf).await?;
        u16::from_be_bytes(u16_bit_buf) as usize
    } else if u8_length == 127 {
        let mut u64_bit_buf = [0u8; 8];
        socket.read_exact(&mut u64_bit_buf).await?;
        u64::from_be_bytes(u64_bit_buf) as usize
    } else {
        u8_length as usize
    };
    let mut payload_buf: Vec<u8> = vec![0; payload_size];
    socket.read_exact(&mut payload_buf).await?;

    for i in 0..payload_size {
        payload_buf[i] ^= mask[i % 4]
    }
    frame.payload = payload_buf;
    Ok(frame)
}

async fn write_frame(socket: &mut TcpStream, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut result: Vec<u8> = vec![FIN_BIT | opcode];

    let payload_length = payload.len() as usize;
    if payload_length <= 125 {
        result.push(payload_length as u8);
    } else if payload_length <= 65535 {
        result.push(126 as u8);
        result.extend((payload_length as u16).to_be_bytes());
    } else {
        result.push(127 as u8);
        result.extend((payload_length as u64).to_be_bytes());
    };
    result.extend_from_slice(payload);
    println!("result: {:?}", result);
    socket.write_all(&result).await?;
    Ok(())
}

async fn handle_socket(socket: &mut TcpStream) -> io::Result<()> {
    let headers = process_headers(socket).await?;
    let accept_key = compute_accept_key(
        &extract_websocket_key(&headers)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Request was malformed"))?,
    );
    send_handshake_response(socket, &accept_key).await?;
    loop {
        let frame = read_frame(socket).await?;
        match frame.opcode {
            0x1 => {
                let text = std::str::from_utf8(&frame.payload).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "invalid utf8 in text frame")
                })?;
                println!("received: {}", text);
                write_frame(socket, 0x1, &frame.payload).await?; // echo for now
            }
            0x2 => {
                println!("received binary frame, {} bytes", frame.payload.len());
                write_frame(socket, 0x2, &frame.payload).await?;
            }
            0x8 => {
                println!("received close signal {:?}", frame);
                write_frame(socket, 0x8, &frame.payload).await?;
                break;
            }
            _ => {
                break;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_socket(&mut socket).await {
                println!("connection ended {:?}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_stuff() {
        let result = compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(result, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
