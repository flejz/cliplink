
use std::io::{self, Read, Write};

/// Maximum frame size we are willing to accept (DoS protection).
/// Tune this to your product constraints.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024; // 16 MiB

/// Fixed header size (bytes) of the frame payload (excluding the u32 length prefix).
pub const HEADER_LEN: usize = 16;

/// Magic bytes to identify your protocol and help reject garbage input.
pub const MAGIC: [u8; 4] = *b"PKT1";

/// Current protocol version.
pub const VERSION: u8 = 1;

/// Application-level framed message (what you logically want to send/receive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Numeric message type (fast to match in code).
    pub msg_type: u16,

    /// Flags for future extension (compression, encryption, etc.). Currently unused.
    pub flags: u8,

    /// Used to correlate responses to requests across a single TCP connection.
    pub request_id: u64,

    /// Optional "type" bytes (string-like in your original design).
    /// Keep it as bytes to avoid UTF-8 assumptions at the transport layer.
    pub ty: Vec<u8>,

    /// The payload bytes.
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying I/O error from Read/Write.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Frame length prefix is too large (probable garbage or attack).
    #[error("frame too large: {len} bytes (max {max})")]
    FrameTooLarge { len: usize, max: usize },

    /// Frame length prefix is too small to even contain the mandatory header.
    #[error("frame too small: {len} bytes (min {min})")]
    FrameTooSmall { len: usize, min: usize },

    /// Wrong magic bytes: not our protocol (or stream desync).
    #[error("bad magic")]
    BadMagic,

    /// Unsupported protocol version.
    #[error("unsupported version: {version}")]
    UnsupportedVersion { version: u8 },

    /// Declared type_len exceeds remaining bytes in the frame.
    #[error("invalid type length")]
    InvalidTypeLen,

    /// Declared payload_len exceeds remaining bytes in the frame.
    #[error("invalid payload length")]
    InvalidPayloadLen,
}

/// Read exactly one length-delimited frame from any `Read` (e.g., TcpStream).
///
/// IMPORTANT:
/// - TCP is a byte stream; you may receive partial data.
/// - This function uses `read_exact` to block until the entire frame is read.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Frame, FrameError> {
    // ---- 1) Read the u32 length prefix (big-endian) ----
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;

    // ---- 2) Validate length before allocating ----
    if frame_len > MAX_FRAME_LEN {
        return Err(FrameError::FrameTooLarge {
            len: frame_len,
            max: MAX_FRAME_LEN,
        });
    }
    if frame_len < HEADER_LEN {
        return Err(FrameError::FrameTooSmall {
            len: frame_len,
            min: HEADER_LEN,
        });
    }

    // ---- 3) Read the entire frame payload ----
    let mut buf = vec![0u8; frame_len];
    r.read_exact(&mut buf)?;

    // ---- 4) Parse fixed header ----
    // Layout:
    // 0..4   magic
    // 4      version
    // 5      flags
    // 6..8   msg_type (u16 be)
    // 8..16  request_id (u64 be)
    if buf[0..4] != MAGIC {
        return Err(FrameError::BadMagic);
    }

    let version = buf[4];
    if version != VERSION {
        return Err(FrameError::UnsupportedVersion { version });
    }

    let flags = buf[5];

    let msg_type = u16::from_be_bytes([buf[6], buf[7]]);

    let request_id = u64::from_be_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);

    // ---- 5) Parse variable sections with bounds checks ----
    let mut i = HEADER_LEN;

    // type_len: u16
    if i + 2 > buf.len() {
        return Err(FrameError::InvalidTypeLen);
    }
    let type_len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;

    // type_bytes: type_len
    if i + type_len > buf.len() {
        return Err(FrameError::InvalidTypeLen);
    }
    let ty = buf[i..i + type_len].to_vec();
    i += type_len;

    // payload_len: u32
    if i + 4 > buf.len() {
        return Err(FrameError::InvalidPayloadLen);
    }
    let payload_len = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
    i += 4;

    // payload_bytes: payload_len
    if i + payload_len > buf.len() {
        return Err(FrameError::InvalidPayloadLen);
    }
    let payload = buf[i..i + payload_len].to_vec();
    i += payload_len;

    // If you want strict parsing, ensure we've consumed the entire frame:
    // This helps detect trailing garbage and keeps framing clean.
    if i != buf.len() {
        // You can choose to allow trailing bytes for future extensions.
        // For now, treat as invalid payload length (or create a dedicated error).
        return Err(FrameError::InvalidPayloadLen);
    }

    Ok(Frame {
        msg_type,
        flags,
        request_id,
        ty,
        payload,
    })
}

/// Write exactly one length-delimited frame to any `Write` (e.g., TcpStream).
///
/// This function:
/// - builds the frame payload in memory
/// - prefixes it with a u32 length
/// - writes both using `write_all`
pub fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> Result<(), FrameError> {
    // ---- 1) Validate sizes before encoding ----
    // Type length is u16 on-wire.
    if frame.ty.len() > u16::MAX as usize {
        return Err(FrameError::InvalidTypeLen);
    }
    // Payload length is u32 on-wire.
    if frame.payload.len() > u32::MAX as usize {
        return Err(FrameError::InvalidPayloadLen);
    }

    // ---- 2) Compute total frame payload length ----
    // frame_payload = header + type_len(2) + type_bytes + payload_len(4) + payload_bytes
    let frame_len = HEADER_LEN
        + 2
        + frame.ty.len()
        + 4
        + frame.payload.len();

    if frame_len > MAX_FRAME_LEN {
        return Err(FrameError::FrameTooLarge {
            len: frame_len,
            max: MAX_FRAME_LEN,
        });
    }

    // ---- 3) Allocate and build the frame payload ----
    let mut buf = Vec::with_capacity(frame_len);

    // Fixed header
    buf.extend_from_slice(&MAGIC);                 // 4
    buf.push(VERSION);                             // 1
    buf.push(frame.flags);                         // 1
    buf.extend_from_slice(&frame.msg_type.to_be_bytes());     // 2
    buf.extend_from_slice(&frame.request_id.to_be_bytes());   // 8

    debug_assert_eq!(buf.len(), HEADER_LEN);

    // Variable: type_len + type bytes
    let ty_len = frame.ty.len() as u16;
    buf.extend_from_slice(&ty_len.to_be_bytes());
    buf.extend_from_slice(&frame.ty);

    // Variable: payload_len + payload bytes
    let payload_len = frame.payload.len() as u32;
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(&frame.payload);

    debug_assert_eq!(buf.len(), frame_len);

    // ---- 4) Write length prefix + frame payload ----
    let len_prefix = (frame_len as u32).to_be_bytes();
    w.write_all(&len_prefix)?;
    w.write_all(&buf)?;
    w.flush()?; // optional; remove if you want the OS to buffer for throughput

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn roundtrip_in_memory() {
        let frame = Frame {
            msg_type: 7,
            flags: 0,
            request_id: 42,
            ty: b"syn".to_vec(),
            payload: b"public keypair".to_vec(),
        };

        // Simulate a network buffer using a Vec<u8>.
        let mut wire = Vec::new();
        write_frame(&mut wire, &frame).unwrap();

        // Now read back from a cursor.
        let mut cursor = std::io::Cursor::new(wire);
        let decoded = read_frame(&mut cursor).unwrap();

        assert_eq!(decoded, frame);
    }
}
