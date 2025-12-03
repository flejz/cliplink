use std::{io::Write, net::TcpStream};

use clap::Parser;
use cliplink_common::Packet;

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

    let mut stream = TcpStream::connect(bind).expect("failed to establish connection");

    let buf = Packet::new("syn", "ack")
        .to_bytes()
        .expect("failed to create packet");

    stream.write(&buf).expect("failed to send packet");
}
