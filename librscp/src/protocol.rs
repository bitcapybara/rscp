use std::{
    fmt::Display, fs::Permissions, io, os::unix::prelude::PermissionsExt, path::PathBuf,
    string::FromUtf8Error,
};

use bytes::{BufMut, Bytes, BytesMut};
use ring::digest;
use s2n_quic::stream::{self, BidirectionalStream};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufStream, BufWriter},
};

const MAGIC_NUMBER: u16 = 63297;
const FRAME_SIZE: usize = 1024 * 1024;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// error from quic stream
    Stream(stream::Error),
    /// utf-8 malformed
    Utf8,
    /// io
    Io(io::Error),
    /// magic number
    MissMagicNumber,
    /// unrecognized bytes seq
    BytesMalformed(String),
    /// stream recv None
    StreamClosed,
    /// path not exists
    PathNotExists(PathBuf),
    /// recv error from server
    FromPeer(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Stream(e) => write!(f, "QUIC stream error: {e}"),
            Error::Utf8 => write!(f, "Invalid UTF-8 string"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::MissMagicNumber => write!(f, "Magic number not invalid"),
            Error::BytesMalformed(s) => write!(f, "Stream bytes Malformed: {s}"),
            Error::StreamClosed => write!(f, "QUIC stream already closed"),
            Error::PathNotExists(p) => write!(f, "Path not exists: {}", p.display()),
            Error::FromPeer(s) => write!(f, "Receive error from server: {s}"),
        }
    }
}

impl From<stream::Error> for Error {
    fn from(e: stream::Error) -> Self {
        Error::Stream(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Self {
        Error::Utf8
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// request from client
pub enum Method {
    /// path in server
    Get(PathBuf),
    /// path in server
    Post(PathBuf),
}

#[derive(Debug)]
struct FileMeta {
    /// file absolute path
    path: PathBuf,
    /// file or empty dir
    is_dir: bool,
    /// permission
    permission: u32,
    /// file size
    file_size: u64,
}

pub struct ProtocolStream(BufStream<BidirectionalStream>);

impl ProtocolStream {
    pub fn new(stream: BidirectionalStream) -> Self {
        Self(BufStream::new(stream))
    }

    async fn close(self) -> Result<()> {
        Ok(self.0.into_inner().close().await?)
    }

    fn buf(&mut self) -> &mut BufStream<BidirectionalStream> {
        &mut self.0
    }

    pub async fn method_recv(&mut self) -> Result<Method> {
        match self.method_decode().await {
            Ok(method) => {
                self.buf().write_all(&[0u8; 1]).await?;
                self.buf().flush().await?;
                Ok(method)
            }
            Err(e) => {
                let mut buf = BytesMut::new();
                buf.put_u8(1);
                let msg = e.to_string();
                buf.put_u16(msg.len() as u16);
                buf.put_slice(msg.as_bytes());
                self.buf().write_buf(&mut buf.freeze()).await?;
                self.buf().flush().await?;
                Err(e)
            }
        }
    }

    async fn method_decode(&mut self) -> Result<Method> {
        // magic number
        if self.buf().read_u16().await? != MAGIC_NUMBER {
            return Err(Error::MissMagicNumber);
        }
        // action
        match self.buf().read_u8().await? {
            0x01 => {
                // check path exists
                let path = self.method_decode_path().await?;
                if !path.exists() {
                    return Err(Error::PathNotExists(path));
                }
                Ok(Method::Get(path))
            }
            0x02 => Ok(Method::Post(self.method_decode_path().await?)),
            n => Err(Error::BytesMalformed(format!("Unknown Method: {n}"))),
        }
    }

    async fn method_decode_path(&mut self) -> Result<PathBuf> {
        let path_len = self.buf().read_u16().await? as usize;
        let mut path_bytes = Vec::from_iter(std::iter::repeat(0u8).take(path_len));
        self.buf().read_exact(&mut path_bytes).await?;
        Ok(PathBuf::from(String::from_utf8(path_bytes.to_vec())?))
    }

    pub async fn method_send(&mut self, method: Method) -> Result<()> {
        // send method
        let mut buf = BytesMut::with_capacity(3);
        buf.put_u16(MAGIC_NUMBER);
        let path = match method {
            Method::Get(path) => {
                buf.put_u8(0x01);
                path
            }
            Method::Post(path) => {
                buf.put_u8(0x02);
                path
            }
        };
        let path = path.to_str().ok_or(Error::Utf8)?;
        buf.put_u16(path.len() as u16);
        buf.put_slice(path.as_bytes());
        self.buf().write_all(&buf.freeze()).await?;
        self.buf().flush().await?;

        // wait for resp
        self.assert_reply().await?;
        Ok(())
    }

    async fn assert_reply(&mut self) -> Result<()> {
        if self.buf().read_u8().await? != 0 {
            let msg_len = self.buf().read_u16().await? as usize;
            let mut msg_bytes = vec![0u8; msg_len];
            self.buf().read_exact(&mut msg_bytes).await?;
            return Err(Error::FromPeer(String::from_utf8(msg_bytes.to_vec())?));
        }
        Ok(())
    }

    pub async fn handle_file_recv(mut self, path: PathBuf) -> Result<()> {
        match self.recv_file(path).await {
            Ok(_) => {
                self.buf().write_all(&[0u8; 1]).await?;
            }
            Err(e) => {
                let mut buf = BytesMut::new();
                let msg = e.to_string();
                buf.put_u16(msg.len() as u16);
                buf.put_slice(msg.as_bytes());
                self.buf().write_all(&buf.freeze()).await?;
            }
        }
        self.close().await.ok();
        Ok(())
    }

    pub async fn recv_file(&mut self, path: PathBuf) -> Result<()> {
        // first chunk, metadata
        let metadata = self.decode_meta().await?;
        if metadata.is_dir {
            fs::create_dir_all(path.join(metadata.path)).await?;
            return Ok(());
        }

        // second chunks, file content
        // write file
        let file_name = metadata
            .path
            .file_name()
            .ok_or(Error::Io(io::Error::from(io::ErrorKind::NotFound)))?;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path.join(file_name))
            .await?;
        file.set_permissions(Permissions::from_mode(metadata.permission))
            .await?;
        let mut bw = BufWriter::new(file.try_clone().await?);
        let mut checksum = digest::Context::new(&digest::SHA256);
        let mut writed = 0u64;
        let mut buf = Box::new([0u8; FRAME_SIZE]);
        while writed < metadata.file_size {
            let read = self.buf().read(&mut *buf).await?;
            let bytes = &buf[0..read];
            // add checksum
            checksum.update(bytes);
            // write to file
            bw.write_all(bytes).await?;
            self.buf().flush().await?;
            writed += read as u64;
        }
        bw.flush().await?;
        let checksum = checksum.finish();

        // third chunk, file size and checksum
        if writed != self.buf().read_u64().await? {
            return Err(Error::BytesMalformed(
                "Writed miss match file size".to_string(),
            ));
        }
        // checksum verify
        let mut checksum_bytes = Box::new([0u8; 32]);
        self.buf().read_exact(&mut *checksum_bytes).await?;
        if checksum.as_ref() != *checksum_bytes {
            return Err(Error::BytesMalformed("Checksum miss match".to_string()));
        }
        Ok(())
    }

    async fn decode_meta(&mut self) -> Result<FileMeta> {
        // path
        let path_len = self.buf().read_u16().await? as usize;
        let mut path_bytes = Vec::from_iter(std::iter::repeat(0u8).take(path_len));
        self.buf().read_exact(&mut path_bytes).await?;
        let path = PathBuf::from(String::from_utf8(path_bytes.to_vec())?);
        // is dir
        let is_dir = self.buf().read_u8().await? == 1;
        if is_dir {
            return Ok(FileMeta {
                path,
                is_dir,
                permission: 0,
                file_size: 0,
            });
        }

        // permission
        let permission = self.buf().read_u32().await?;
        // file size
        let file_size = self.buf().read_u64().await?;

        Ok(FileMeta {
            path,
            is_dir,
            permission,
            file_size,
        })
    }

    pub async fn handle_file_send(mut self, path: PathBuf) -> Result<()> {
        if !path.exists() {
            return Err(Error::Io(io::Error::from(io::ErrorKind::NotFound)));
        }
        let mut buf = BytesMut::new();
        // path
        let path_bytes = path.to_str().ok_or(Error::Utf8)?.as_bytes();
        buf.put_u16(path_bytes.len() as u16);
        buf.put_slice(path_bytes);
        // is dir
        let is_dir = fs::metadata(&path).await?.is_dir();
        buf.put_u8(is_dir as u8);
        if is_dir {
            return Ok(());
        }
        // file
        let file = OpenOptions::new().read(true).open(path).await?;
        // permission
        let metadata = file.metadata().await?;
        let file_size = metadata.len();
        let permission = metadata.permissions().mode();
        buf.put_u32(permission);
        // file chunk count
        buf.put_u64(file_size);
        // first send, file metadata
        self.buf().write_all(&buf.freeze()).await?;
        self.buf().flush().await?;

        // read file
        let mut br = BufReader::new(file);
        let mut read_buf = Box::new([0u8; FRAME_SIZE]);
        let mut checksum = digest::Context::new(&digest::SHA256);
        loop {
            let read = br.read(&mut *read_buf).await?;
            if read == 0 {
                break;
            }
            // send chunk
            let frame = Bytes::from(read_buf[0..read].to_vec());
            checksum.update(&frame);
            // second send file content
            self.buf().write_all(&frame).await?;
            self.buf().flush().await?;
            if read < FRAME_SIZE {
                break;
            }
        }

        let mut buf = BytesMut::new();
        // file size
        buf.put_u64(file_size);
        // checksum
        buf.put_slice(checksum.finish().as_ref());
        // third send, file size and checksum
        self.buf().write_all(&buf.freeze()).await?;
        self.buf().flush().await?;

        // wait for reply
        self.assert_reply().await?;
        Ok(())
    }
}
