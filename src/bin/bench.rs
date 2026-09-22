use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECTIONS: i32 = 20140;

async fn connect() -> Option<u128> {
    let now = Instant::now();
    let mut stream = TcpStream::connect("127.0.0.1:8080").await.ok()?;
    stream.write_all(b"hello, world").await.ok()?;
    stream.shutdown().await.ok()?;
    let mut buffer: Vec<u8> = Vec::new();
    stream.read_to_end(&mut buffer).await.ok()?;
    println!("buffer output: {:?}", buffer);
    Some(now.elapsed().as_millis())
}

#[tokio::main]
async fn main() {
    let mut results = vec![];
    let mut handles = vec![];
    for _ in 0..CONNECTIONS {
        let h = tokio::spawn(connect());
        handles.push(h);
    }
    for h in handles {
        let r = h.await.unwrap();
        if let Some(duration) = r {
            results.push(duration);
        }
    }
    let min = results.iter().min().unwrap();
    let max = results.iter().max().unwrap();
    let sum: u128 = results.iter().sum();
    let avg: u128 = sum / results.len() as u128;
    println!("Results for {} connections:", CONNECTIONS);
    println!("avg: {:?}ms, min: {:?}ms, max {:?}ms", avg, min, max);
}
