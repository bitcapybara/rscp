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
use s2n_quic::stream::{self, ReceiveStream, SendStream};
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

struct File {
    /// file absolute path
    path: PathBuf,
    /// is dir
    is_dir: bool,
    /// permission
    permission: u32,
}

impl File {
    pub async fn handle_recv(stream: &mut ReceiveStream) -> Result<()> {
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
        // magic number
        assert_len(buf, 2)?;
        if buf.get_u16() != MAGIC_NUMBER {
            return Err(Error::MissMagicNumber);
        }
        // path
        assert_len(buf, 2)?;
        let path_len = buf.get_u16() as usize;
        assert_len(buf, path_len)?;
        let path_bytes = buf.split_to(path_len).to_vec();
        let path = PathBuf::from(String::from_utf8(path_bytes)?);

        // is dir
        assert_len(buf, 1)?;
        let is_dir = buf.get_u8() == 1;

        // permission
        assert_len(buf, 4)?;
        let permission = buf.get_u32();

        Ok(File {
            path,
            is_dir,
            permission,
        })
    }

    pub async fn handle_send(stream: &mut SendStream, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::Malformed);
        }
        // path
        let path = path.to_path_buf();
        // is dir
        let is_dir = path.is_dir();
        // file
        let file = OpenOptions::new().read(true).open(path).await?;
        // permission
        let permission = file.metadata().await?.permissions().mode();
        Ok(())
    }
}

fn assert_len(buf: &Bytes, len: usize) -> Result<()> {
    if buf.len() < len {
        return Err(Error::Malformed);
    }
    Ok(())
}
