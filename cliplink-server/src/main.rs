use cliplink_common::{PACKET_SIZE, Packet};
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    ops::DerefMut,
};

use crate::sm::StreamState;

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

        std::thread::spawn(move || {
            handle(stream);
        });
    }
}

fn handle(mut stream: TcpStream) {
    let mut buf = Packet::new_buffer();

    let mut unwrap = || -> usize {
        match stream.read(&mut buf) {
            Ok(len) => len,
            Err(err) => {
                eprintln!("read failure, closing socket: {err:?}");
                stream
                    .shutdown(std::net::Shutdown::Both)
                    .expect("failed to shutdown");

                panic!("{err}");
            }
        }
    };

    let buf_len = unwrap();
    buf[buf_len..].fill(0x0);

    let packet = Packet::from_bytes(&buf).unwrap();
    //let state = StreamState::default();
    //let state = state.consume(StreamPayload::from(&packet)).unwrap();
    //let state = state.consume(StreamPayload::from(&packet)).unwrap();
    //let _state = state.consume(StreamPayload::from(&packet)).unwrap();

    dbg!(packet);
}
