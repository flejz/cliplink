use std::{io::Write, net::TcpStream};

use clap::Parser;
use cliplink_common::{PACKET_SIZE, Packet};
use cliplink_crypto::RsaPrivKey;

use crate::conn::{Connection, ConnectionError};

mod conn;

/// Cliplink client
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Port to connect in the host machine
    #[arg(short, long, default_value = "6166")]
    port: u16,

    /// Host machine address
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
}

fn main() {
    let args = Args::parse();
    let addr = args.host;
    let port = args.port;

    let bind = format!("{addr}:{port}");

    let stream = TcpStream::connect(bind).expect("failed to establish connection");

    handle(stream).expect("failed to handle")
}

fn handle(stream: TcpStream) -> Result<(), ConnectionError> {
    let mut buf = [0u8; PACKET_SIZE];
    let conn = Connection::from(stream);

    let mut conn = conn.send_ssh_key()?;
    conn.read_bytes(&mut buf)?;
    let mut conn = conn.parse_aes256_key(&Packet::from_bytes(&buf))?;

    conn.write_packet_sec(Packet::new(b"eita", b"porra"))?;

    Ok(())
}
