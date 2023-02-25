use std::{
    fmt::Display,
    fs::Permissions,
    io,
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
    string::FromUtf8Error,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::digest;
use s2n_quic::stream::{self, ReceiveStream};
use tokio::{
    fs::OpenOptions,
    io::{AsyncWriteExt, BufWriter},
};

const MAGIC_NUMBER: u16 = 9972;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    MissMagicNumber,
    UnknownHandshake,
    Malformed,
    StreamClosed,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl From<stream::Error> for Error {
    fn from(value: stream::Error) -> Self {
        todo!()
    }
}

impl From<FromUtf8Error> for Error {
    fn from(value: FromUtf8Error) -> Self {
        todo!()
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        todo!()
    }
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
            return Err(Error::MissMagicNumber);
        }

        // get handshake type
        if buf.is_empty() {
            return Err(Error::Malformed);
        }
        match buf.get_u8() {
            0x01 => Ok(Handshake::Recv(Self::decode_path(&mut buf)?)),
            0x02 => Ok(Handshake::Send(Self::decode_path(&mut buf)?)),
            _ => Err(Error::UnknownHandshake),
        }
    }

    fn decode_path(buf: &mut Bytes) -> Result<PathBuf> {
        if buf.len() < 2 {
            return Err(Error::Malformed);
        }

        let path_len = buf.get_u16() as usize;
        if buf.len() < path_len {
            return Err(Error::Malformed);
        }
        let path_bytes = buf.split_to(path_len).to_vec();
        Ok(PathBuf::from(String::from_utf8(path_bytes)?))
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
        let path_str = path.to_str().ok_or(Error::Malformed)?;
        buf.put_u16(path_str.len() as u16);
        buf.extend_from_slice(path_str.as_bytes());
        Ok(())
    }
}

struct File {
    /// file absolute path
    path: PathBuf,
    /// permission
    permission: u32,
}

impl File {
    pub async fn recv_file(stream: &mut ReceiveStream) -> Result<()> {
        let mut buf = stream.receive().await?.ok_or(Error::StreamClosed)?;
        let metadata = Self::decode(&mut buf)?;

        // write file
        let mut writed = 0;
        let file = OpenOptions::new().append(true).open(metadata.path).await?;
        file.set_permissions(Permissions::from_mode(metadata.permission))
            .await?;
        let mut file = BufWriter::new(file);
        let mut checksum = digest::Context::new(&digest::SHA256);
        while let Some(buf) = stream.receive().await? {
            // add checksum
            checksum.update(&buf);
            // write to file
            file.write_all(&buf).await?;
            // total count
            writed += buf.len();
        }
        file.flush().await?;
        // check total bytes count
        let mut buf = stream.receive().await?.ok_or(Error::Malformed)?;
        assert_len(&buf, 8)?;
        if writed != buf.get_u64() as usize {
            return Err(Error::Malformed);
        }
        // checksum verify
        assert_len(&buf, 32)?;
        if checksum.finish().as_ref() != buf.split_to(32) {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn decode(buf: &mut Bytes) -> Result<Self> {
        // path
        assert_len(buf, 2)?;
        let path_len = buf.get_u16() as usize;
        assert_len(buf, path_len)?;
        let path_bytes = buf.split_to(path_len).to_vec();
        let path = PathBuf::from(String::from_utf8(path_bytes)?);

        // permission
        assert_len(buf, 4)?;
        let permission = buf.get_u32();

        Ok(File { path, permission })
    }
}

fn assert_len(buf: &Bytes, len: usize) -> Result<()> {
    if buf.len() < len {
        return Err(Error::Malformed);
    }
    Ok(())
}
