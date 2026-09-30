use base64::{Engine, engine::general_purpose::STANDARD};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

const DELIM: &[u8] = b"\r\n\r\n";
const MAGIC_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const FIN_BIT: u8 = 0b1000_0000;
const OPCODE_MASK: u8 = 0b0000_1111;
const MASK_BIT: u8 = 0b1000_0000;
const LENGTH_MASK: u8 = 0b0111_1111;

#[derive(Debug, Default, Clone)]
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

async fn read_frame(r_socket: &mut OwnedReadHalf) -> io::Result<Frame> {
    // frame header parse
    let mut frame_header = [0u8; 2];
    r_socket.read_exact(&mut frame_header).await?;
    let mut frame = Frame {
        fin: frame_header[0] & FIN_BIT != 0,
        opcode: frame_header[0] & OPCODE_MASK,
        payload: vec![],
    };
    let mask_flag: bool = frame_header[1] & MASK_BIT != 0;
    // unmasking
    let mut mask = [0u8; 4];
    if mask_flag {
        r_socket.read_exact(&mut mask).await?;
    }

    // content length
    let u8_length = frame_header[1] & LENGTH_MASK;
    let payload_size: usize = if u8_length == 126 {
        let mut u16_bit_buf = [0u8; 2];
        r_socket.read_exact(&mut u16_bit_buf).await?;
        u16::from_be_bytes(u16_bit_buf) as usize
    } else if u8_length == 127 {
        let mut u64_bit_buf = [0u8; 8];
        r_socket.read_exact(&mut u64_bit_buf).await?;
        u64::from_be_bytes(u64_bit_buf) as usize
    } else {
        u8_length as usize
    };
    let mut payload_buf: Vec<u8> = vec![0; payload_size];
    r_socket.read_exact(&mut payload_buf).await?;

    for i in 0..payload_size {
        payload_buf[i] ^= mask[i % 4]
    }
    frame.payload = payload_buf;
    Ok(frame)
}

async fn write_frame(w_socket: &mut OwnedWriteHalf, opcode: u8, payload: &[u8]) -> io::Result<()> {
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
    w_socket.write_all(&result).await?;
    Ok(())
}

async fn write_task(
    w_socket: &mut OwnedWriteHalf,
    mut rx: UnboundedReceiver<Frame>,
) -> io::Result<()> {
    while let Some(frame) = rx.recv().await {
        write_frame(w_socket, frame.opcode, &frame.payload).await?;
    }
    Ok(())
}

async fn read_task(
    r_socket: &mut OwnedReadHalf,
    registry: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Frame>>>>,
    own_addr: SocketAddr,
) -> io::Result<()> {
    loop {
        let frame: Frame = read_frame(r_socket).await?;

        match frame.opcode {
            0x1 => {
                let text = std::str::from_utf8(&frame.payload).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "invalid utf8 in text frame")
                })?;
                println!("received: {}", text);
                let map = registry.lock().unwrap();
                for (key, tx) in map.iter() {
                    if *key != own_addr {
                        let _ = tx.send(frame.clone());
                    }
                }
            }
            0x2 => {
                println!("received binary frame, {} bytes", frame.payload.len());
                let map = registry.lock().unwrap();
                for (key, tx) in map.iter() {
                    if *key != own_addr {
                        let _ = tx.send(frame.clone());
                    }
                }
            }
            0x8 => {
                let mut map = registry.lock().unwrap();
                let tx = map.get(&own_addr).unwrap();
                let _ = tx.send(frame.clone());
                map.remove(&own_addr);
                break;
            }
            _ => {
                let mut map = registry.lock().unwrap();
                map.remove(&own_addr);
                break;
            }
        }
    }
    Ok(())
}

async fn handle_socket(
    mut socket: TcpStream,
    addr: SocketAddr,
    registry: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Frame>>>>,
) -> io::Result<()> {
    let headers = process_headers(&mut socket).await?;

    let accept_key = compute_accept_key(
        &extract_websocket_key(&headers)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Request was malformed"))?,
    );
    send_handshake_response(&mut socket, &accept_key).await?;

    let (mut read_half, mut write_half) = socket.into_split();

    let (tx, rx): (UnboundedSender<Frame>, UnboundedReceiver<Frame>) =
        mpsc::unbounded_channel::<Frame>();

    {
        let mut map = registry.lock().unwrap();
        map.insert(addr, tx);
    }

    tokio::spawn(async move {
        if let Err(e) = write_task(&mut write_half, rx).await {
            // if there's an error in writing what needs to happen
            // any upstream messages are lost our channel should be considered closed
            println!("Error while writing: {}", e)
        }
    });

    tokio::spawn(async move {
        if let Err(e) = read_task(&mut read_half, Arc::clone(&registry), addr).await {
            println!("Error while reading: {}", e);
            let mut map = registry.lock().unwrap();
            map.remove(&addr);
        }
    });

    // loop {
    //     let frame = read_frame(socket).await?;
    //     match frame.opcode {
    //         0x1 => {
    //             let text = std::str::from_utf8(&frame.payload).map_err(|_| {
    //                 Error::new(ErrorKind::InvalidData, "invalid utf8 in text frame")
    //             })?;
    //             println!("received: {}", text);
    //             write_frame(socket, 0x1, &frame.payload).await?; // echo for now
    //         }
    //         0x2 => {
    //             println!("received binary frame, {} bytes", frame.payload.len());
    //             write_frame(socket, 0x2, &frame.payload).await?;
    //         }
    //         0x8 => {
    //             println!("received close signal {:?}", frame);
    //             write_frame(socket, 0x8, &frame.payload).await?;
    //             break;
    //         }
    //         _ => {
    //             break;
    //         }
    //     }
    // }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let registry: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Frame>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    loop {
        let (socket, addr) = listener.accept().await?;
        let thread_registry = Arc::clone(&registry);
        tokio::spawn(async move {
            if let Err(e) = handle_socket(socket, addr, thread_registry).await {
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
