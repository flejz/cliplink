use std::net::TcpStream;

use clap::Parser;
use cliplink_common::{PACKET_SIZE, Packet};

use crate::{
    conn::Connection,
    session::{Session, SessionError},
};

mod conn;
mod session;

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

    /// Host machine address
    #[arg(short, long)]
    clip: Option<String>,
}

fn main() {
    let args = Args::parse();
    let addr = args.host;
    let port = args.port;

    let bind = format!("{addr}:{port}");

    let stream = TcpStream::connect(bind).expect("failed to establish connection");

    handle(stream).expect("failed to handle")
}

fn handle(stream: TcpStream) -> Result<(), SessionError> {
    let mut buf = [0u8; PACKET_SIZE];
    let conn = Connection::from(stream);

    let mut conn = conn.send_ssh_key()?;
    conn.read_bytes(&mut buf).unwrap(); // TODO: fix
    let conn = conn.parse_aes256_key(&Packet::from_bytes(&buf))?;
    let mut session = Session::new(conn);

    session.paste(None, b"xungoro".to_vec())?;
    let clip = session.copy(None)?;
    println!(
        "{}",
        String::from_utf8(clip).expect("failed to serialize string")
    );

    Ok(())
}
