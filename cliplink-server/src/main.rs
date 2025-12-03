use cliplink_common::Packet;
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
};

fn main() {
    let addr = std::env::var("CL_ADDR").unwrap_or("127.0.0.1".into());
    let port = std::env::var("CL_PORT").unwrap_or("6166".into());
    let bind = format!("{addr}:{port}");

    let socket = TcpListener::bind(&bind).expect("failed to bind to {bind}");

    println!("listening on {bind:?}");

    for stream in socket.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("incoming connection error: {err:?}");
                continue;
            }
        };

        handle(stream);
    }
}

fn handle(mut stream: TcpStream) {
    std::thread::spawn(move || {
        println!("socket connection");
        let mut buf = [0_u8; 1024];
        let _buf_len = match stream.read(&mut buf) {
            Ok(len) => len,
            Err(err) => {
                eprintln!("read failure, closing socket: {err:?}");
                stream
                    .shutdown(std::net::Shutdown::Both)
                    .expect("failed to shutdown");
                return;
            }
        };

        dbg!(Packet::parse_bytes(&buf).unwrap());
    });
}
