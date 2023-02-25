use std::{
    fmt::Display,
    path::{Path, PathBuf},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};

const MAGIC_NUMBER: u16 = 9972;

type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Debug)]
pub enum ProtocolError {
    MissMagicNumber,
    UnknownHandshake,
    Malformed,
}

impl std::error::Error for ProtocolError {}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

pub struct FileMeta {
    is_dir: bool,
    permission: u32,
}

pub enum Handshake {
    // copy file from remote to local
    Recv(PathBuf),
    // copy file from local to remote
    Send(PathBuf),
}

impl Handshake {
    pub fn decode(mut buf: Bytes) -> Result<Self> {
        // check magic number
        if buf.len() < 2 || buf.get_u16() != MAGIC_NUMBER {
            return Err(ProtocolError::MissMagicNumber);
        }

        // get handshake type
        if buf.is_empty() {
            return Err(ProtocolError::Malformed);
        }
        match buf.get_u8() {
            1 => Ok(Handshake::Recv(Self::decode_path(&mut buf)?)),
            2 => Ok(Handshake::Send(Self::decode_path(&mut buf)?)),
            _ => Err(ProtocolError::UnknownHandshake),
        }
    }

    fn decode_path(buf: &mut Bytes) -> Result<PathBuf> {
        if buf.len() < 2 {
            return Err(ProtocolError::Malformed);
        }

        let path_len = buf.get_u16() as usize;
        if buf.len() < path_len {
            return Err(ProtocolError::Malformed);
        }
        let path_bytes = buf.split_to(path_len).to_vec();
        match String::from_utf8(path_bytes) {
            Ok(path) => Ok(PathBuf::from(path)),
            Err(_) => Err(ProtocolError::Malformed),
        }
    }

    pub fn encode(self) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        buf.put_u16(MAGIC_NUMBER);
        let path = match self {
            Handshake::Recv(path) => {
                buf.put_u8(1);
                path
            }
            Handshake::Send(path) => {
                buf.put_u8(2);
                path
            }
        };
        Self::encode_path(&mut buf, path)?;
        Ok(buf.freeze())
    }

    fn encode_path(buf: &mut BytesMut, path: PathBuf) -> Result<()> {
        let path_str = path.to_str().ok_or(ProtocolError::Malformed)?;
        buf.put_u16(path_str.len() as u16);
        buf.extend_from_slice(path_str.as_bytes());
        Ok(())
    }
}
