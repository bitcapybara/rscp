use std::{
    fmt::Display, fs::Permissions, io, os::unix::prelude::PermissionsExt, path::PathBuf,
    string::FromUtf8Error,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::digest;
use s2n_quic::stream::{self, BidirectionalStream};
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
};

const MAGIC_NUMBER: u16 = 9972;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    MissMagicNumber,
    UnknownHandshake,
    Malformed,
    StreamClosed,
    PathInvalid,
    FromServer(String),
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

/// request from client
pub enum Method {
    /// path in server
    Get(PathBuf),
    /// path in server
    Post(PathBuf),
}

impl Method {
    pub async fn recv(stream: &mut BidirectionalStream) -> Result<Self> {
        match Self::decode(stream).await {
            Ok(method) => {
                stream.send(Bytes::from_static(&[0u8])).await?;
                Ok(method)
            }
            Err(e) => {
                let mut buf = BytesMut::new();
                buf.put_u8(1);
                let msg = e.to_string();
                buf.put_u16(msg.len() as u16);
                buf.put_slice(msg.as_bytes());
                stream.send(buf.freeze()).await?;
                Err(e)
            }
        }
    }
    async fn decode(stream: &mut BidirectionalStream) -> Result<Self> {
        match stream.receive().await? {
            Some(mut buf) => {
                // magic number
                assert_len(&buf, 2)?;
                if buf.get_u16() != MAGIC_NUMBER {
                    // TODO send error message
                    return Err(Error::MissMagicNumber);
                }
                // action
                assert_len(&buf, 1)?;
                match buf.get_u8() {
                    0x01 => {
                        // check path exists
                        let path = Self::decode_path(&mut buf).await?;
                        if !path.exists() {
                            return Err(Error::PathInvalid);
                        }
                        Ok(Self::Get(path))
                    }
                    0x02 => Ok(Self::Post(Self::decode_path(&mut buf).await?)),
                    _ => Err(Error::Malformed),
                }
            }
            None => Err(Error::StreamClosed),
        }
    }
    async fn decode_path(buf: &mut Bytes) -> Result<PathBuf> {
        assert_len(buf, 2)?;
        let path_len = buf.get_u16() as usize;
        let path_bytes = buf.split_to(path_len);
        Ok(PathBuf::from(String::from_utf8(path_bytes.to_vec())?))
    }

    pub async fn send(self, stream: &mut BidirectionalStream) -> Result<()> {
        // send method
        let mut buf = BytesMut::with_capacity(3);
        buf.put_u16(MAGIC_NUMBER);
        let n = match self {
            Method::Get(_) => 0x01,
            Method::Post(_) => 0x02,
        };
        buf.put_u8(n);
        stream.send(buf.freeze()).await?;

        // wait for resp
        let mut buf = stream.receive().await?.ok_or(Error::StreamClosed)?;
        assert_len(&buf, 1)?;
        if buf.get_u8() != 0 {
            assert_len(&buf, 2)?;
            let msg_len = buf.get_u16() as usize;
            let msg_bytes = buf.split_to(msg_len);
            return Err(Error::FromServer(String::from_utf8(msg_bytes.to_vec())?));
        }
        Ok(())
    }
}

pub struct File {
    /// file absolute path
    path: PathBuf,
    /// file or empty dir
    is_dir: bool,
    /// permission
    permission: u32,
}

impl File {
    pub async fn handle_recv(mut stream: BidirectionalStream, path: PathBuf) -> Result<()> {
        let mut buf = stream.receive().await?.ok_or(Error::StreamClosed)?;
        let metadata = Self::decode(&mut buf)?;

        // write file
        let file = OpenOptions::new()
            .append(true)
            .open(path.join(metadata.path))
            .await?;
        file.set_permissions(Permissions::from_mode(metadata.permission))
            .await?;
        let mut bw = BufWriter::new(file.try_clone().await?);
        let mut checksum = digest::Context::new(&digest::SHA256);
        while let Some(buf) = stream.receive().await? {
            // add checksum
            checksum.update(&buf);
            // write to file
            bw.write_all(&buf).await?;
        }
        bw.flush().await?;
        let checksum = checksum.finish();
        // check total bytes count
        let writed = file.metadata().await?.len();
        let mut buf = stream.receive().await?.ok_or(Error::Malformed)?;
        assert_len(&buf, 8)?;
        if writed != buf.get_u64() {
            return Err(Error::Malformed);
        }
        // checksum verify
        assert_len(&buf, 32)?;
        if checksum.as_ref() != buf.split_to(32) {
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

    pub async fn handle_send(mut stream: BidirectionalStream, path: PathBuf) -> Result<()> {
        if !path.exists() {
            return Err(Error::Malformed);
        }
        let mut buf = BytesMut::new();
        // path
        let path = path.canonicalize()?;
        let path_bytes = path.to_str().ok_or(Error::Malformed)?.as_bytes();
        buf.put_u16(path_bytes.len() as u16);
        buf.put_slice(path_bytes);
        // is dir
        buf.put_u8(path.is_dir() as u8);
        // file
        let file = OpenOptions::new().read(true).open(path).await?;
        // permission
        let metadata = file.metadata().await?;
        let file_size = metadata.len();
        let permission = metadata.permissions().mode();
        buf.put_u32(permission);

        // read file
        const FRAME_SIZE: usize = 1024 * 10;
        let mut br = BufReader::new(file);
        let read_buf = [0u8; FRAME_SIZE];
        let mut checksum = digest::Context::new(&digest::SHA256);
        loop {
            let read = br.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            // send chunk
            let frame = Bytes::from(read_buf[0..read].to_vec());
            checksum.update(&frame);
            stream.send(frame).await?;
            if read < FRAME_SIZE {
                break;
            }
        }
        let mut buf = BytesMut::new();
        // file size
        buf.put_u64(file_size);
        // checksum
        buf.put_slice(checksum.finish().as_ref());
        stream.send(buf.freeze()).await?;
        Ok(())
    }
}

fn assert_len(buf: &Bytes, len: usize) -> Result<()> {
    if buf.len() < len {
        return Err(Error::Malformed);
    }
    Ok(())
}
