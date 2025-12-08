use std::{io::Write, net::TcpStream};

use clap::Parser;
use cliplink_common::{Packet, ToBytes};
use cliplink_crypto::RsaPrivKey;

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

    let rsa_priv_key = RsaPrivKey::default();
    let rsa_pub_key = rsa_priv_key.pub_key();

    let buf = Packet::new(
        "syn",
        rsa_pub_key
            .to_openssh(None)
            .expect("failed to generate openssh key repr")
            .as_str(),
    )
    .to_bytes()
    .expect("failed to create packet");

    stream.write(&buf).expect("failed to send packet");
}
