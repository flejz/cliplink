use std::{io::Read, net::TcpListener, str::Bytes};
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

        // |--------------------------------| 64 bytes
        // 0                16
        // |    type len    |  payload len  |
        // 32
        // |            type str            |
        // 64                               1024
        // |           payload str          |

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
fn into_fixed_8(src: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];

    // copy only what fits
    let n = src.len().min(8);
    out[..n].copy_from_slice(&src[..n]);

    out
}

#[derive(Debug)]
pub struct Packet<'a> {
    ty: &'a str,
    pl: &'a str,
}

impl<'a> Packet<'a> {
    fn parse_bytes(buf: &'a [u8; 1024]) -> Self {
        let ty_len = usize::from_le_bytes(into_fixed_8(&buf[0..8]));
        let pl_len = usize::from_le_bytes(into_fixed_8(&buf[8..16]));

        let ty = str::from_utf8(&buf[16..(16 + ty_len)]).unwrap();
        let pl = str::from_utf8(&buf[32..(32 + pl_len)]).unwrap();

        Self { ty, pl }
    }
}

#[cfg(test)]
mod test {
    use crate::Packet;

    #[test]
    fn check_bytestream_parsing() {
        let ty = "syn";
        let pl = "public keypair";
        let mut buf = [0u8; 1024];

        let ty_bytes = ty.as_bytes();
        let ty_bytes = [0u8; 16]
            .iter()
            .enumerate()
            .map(|(i, by)| if i < ty_bytes.len() { ty_bytes[i] } else { *by })
            .collect::<Vec<u8>>();

        buf[0..8].copy_from_slice(ty.len().to_le_bytes().as_slice());
        buf[8..16].copy_from_slice(pl.len().to_le_bytes().as_slice());
        buf[16..32].copy_from_slice(ty_bytes.as_slice());
        buf[32..(32 + pl.len())].copy_from_slice(pl.as_bytes());

        let packet = Packet::parse_bytes(&buf);

        dbg!(packet);

        assert!(false);
    }
}
