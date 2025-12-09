use cliplink_common::{PACKET_SIZE, Packet};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

use crate::conn::{Connection, ConnectionError};

mod conn;

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

fn handle(stream: TcpStream) -> Result<(), ConnectionError> {
    let mut buf = [0u8; PACKET_SIZE];
    let mut conn = Connection::from(stream);

    let _ = conn.read_bytes(&mut buf)?;
    let conn = conn.validate_ssh_key(&Packet::from_bytes(&buf))?;
    let mut conn = conn.gen_aes256_key()?;

    loop {
        let packet = conn.read_packet_sec()?;

        dbg!(
            String::from_utf8_lossy(packet.ty()?),
            String::from_utf8_lossy(packet.payload()?)
        );
    }

    Ok(())
}
