use cliplink_common::Packet;
use std::{io::Read, net::TcpListener};
use tracing::{error, info};

fn main() {
    let addr = std::env::var("CL_ADDR").unwrap_or("127.0.0.1".into());
    let port = std::env::var("CL_PORT").unwrap_or("6166".into());
    let bind = format!("{addr}:{port}");

    let socket = TcpListener::bind(bind).expect("failed to bind to {bind}");

    for stream in socket.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                error!(?err, "incoming connection error");
                continue;
            }
        };

        info!("new socket connection");
        let mut buf = [0_u8; 1024];
        let buf_len = match stream.read(&mut buf) {
            Ok(len) => len,
            Err(err) => {
                error!(?err, "read failure, closing socket");
                stream
                    .shutdown(std::net::Shutdown::Both)
                    .expect("failed to shutdown");
                continue;
            }
        };

        Packet::parse_bytes(&buf);
    }
}
