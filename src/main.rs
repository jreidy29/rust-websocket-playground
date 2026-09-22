use base64::{Engine, engine::general_purpose::STANDARD};
use sha1::{Digest, Sha1};
use std::io::{Error, ErrorKind};
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DELIM: &[u8] = b"\r\n\r\n";
const MAGIC_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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

async fn handle_socket(socket: &mut TcpStream) -> io::Result<()> {
    let headers = process_headers(socket).await?;
    let accept_key = compute_accept_key(
        &extract_websocket_key(&headers)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Request was malformed"))?,
    );
    send_handshake_response(socket, &accept_key).await
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let _ = handle_socket(&mut socket).await;
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
