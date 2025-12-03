use cliplink_common::Packet;
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
};

use crate::sm::{StreamPayload, StreamState, StreamStateTransition};

mod sm;

fn main() {
    let addr = std::env::var("CL_ADDR").unwrap_or("127.0.0.1".into());
    let port = std::env::var("CL_PORT").unwrap_or("6166".into());
    let bind = format!("{addr}:{port}");

    let socket = TcpListener::bind(&bind).expect("failed to bind to {bind}");

    println!("listening on {:?}", socket.local_addr().unwrap());

    for stream in socket.incoming() {
        let stream = match stream {
            Ok(stream) => {
                println!("incoming connection: {:?}", stream.peer_addr().unwrap());
                stream
            }
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

        let packet = Packet::parse_bytes(&buf).unwrap();
        let state = StreamState::new(stream);
        let state = state.transition(StreamPayload::from(&packet)).unwrap();
        let state = state.transition(StreamPayload::from(&packet)).unwrap();
        let _state = state.transition(StreamPayload::from(&packet)).unwrap();

        dbg!(Packet::parse_bytes(&buf).unwrap());
    });
}
