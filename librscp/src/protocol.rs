use std::{
    fmt::Display,
    fs::Permissions,
    io,
    ops::{Deref, DerefMut},
    os::unix::prelude::PermissionsExt,
    path::PathBuf,
    string::FromUtf8Error,
};

use bytes::{BufMut, Bytes, BytesMut};
use ring::digest;
use s2n_quic::stream::{self, BidirectionalStream};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufStream, BufWriter},
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
pub struct File {
    /// file absolute path
    path: PathBuf,
    /// file or empty dir
    is_dir: bool,
    /// permission
    permission: u32,
    /// file size
    file_size: u64,
}

struct ProtocolStream(BufStream<BidirectionalStream>);

impl Deref for ProtocolStream {
    type Target = BufStream<BidirectionalStream>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ProtocolStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ProtocolStream {
    pub async fn method_recv(&mut self) -> Result<Method> {
        match self.method_decode().await {
            Ok(method) => {
                self.write_all(&[0u8; 1]).await?;
                Ok(method)
            }
            Err(e) => {
                let mut buf = BytesMut::new();
                buf.put_u8(1);
                let msg = e.to_string();
                buf.put_u16(msg.len() as u16);
                buf.put_slice(msg.as_bytes());
                self.write_buf(&mut buf.freeze()).await?;
                Err(e)
            }
        }
    }
    async fn method_decode(&mut self) -> Result<Method> {
        // magic number
        if self.read_u16().await? != MAGIC_NUMBER {
            return Err(Error::MissMagicNumber);
        }
        // action
        match self.read_u8().await? {
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
        let path_len = self.read_u16().await? as usize;
        let mut path_bytes = Vec::from_iter(std::iter::repeat(0u8).take(path_len));
        self.read_exact(&mut path_bytes).await?;
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
        self.write_all(&buf.freeze()).await?;

        // wait for resp
        self.assert_reply().await?;
        Ok(())
    }
    async fn assert_reply(&mut self) -> Result<()> {
        if self.read_u8().await? != 0 {
            let msg_len = self.read_u16().await? as usize;
            let msg_bytes = self.split_to(msg_len);
            return Err(Error::FromPeer(String::from_utf8(msg_bytes.to_vec())?));
        }

        Ok(())
    }
}

pub async fn handle_recv<T>(stream: T, path: PathBuf) -> Result<()>
where
    T: AsyncRead + AsyncWrite,
{
    let (recv_stream, send_stream) = stream.split();
    let mut buf_stream = BufReader::new(recv_stream);
    match Self::recv(&mut send_stream, path).await {
        Ok(_) => {
            println!("Send okkk");
            Ok(stream.send(Bytes::from_static(&[0u8])).await?)
        }
        Err(e) => {
            println!("Send errrr");
            let mut buf = BytesMut::new();
            let msg = e.to_string();
            buf.put_u16(msg.len() as u16);
            buf.put_slice(msg.as_bytes());
            Ok(stream.send(buf.freeze()).await?)
        }
    }
}
pub async fn recv(stream: &mut BufReader<BidirectionalStream>, path: PathBuf) -> Result<()> {
    println!("recvvvvvv 1");
    // first chunk, metadata
    let metadata = Self::decode(&mut buf)?;
    if metadata.is_dir {
        fs::create_dir_all(path.join(metadata.path)).await?;
        return Ok(());
    }
    println!("{:?}", metadata);
    println!("path: {}", path.display());

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
    while writed < metadata.file_size {
        println!("recvvvvvv 2");
        let buf = stream.receive().await?.ok_or(Error::StreamClosed)?;
        println!("recvvvvvv 2.1");
        // add checksum
        checksum.update(&buf);
        // write to file
        bw.write_all(&buf).await?;
    }
    bw.flush().await?;
    let checksum = checksum.finish();

    // third chunk, file size and checksum
    println!("recvvvvvv 3");
    let mut buf = stream.receive().await?.ok_or(Error::StreamClosed)?;
    println!("recvvvvvv 3.1");
    assert_len(buf, 8)?;
    if writed != buf.get_u64() {
        return Err(Error::BytesMalformed(
            "Writed miss match file size".to_string(),
        ));
    }
    // checksum verify
    assert_len(buf, 32)?;
    if checksum.as_ref() != buf.split_to(32) {
        return Err(Error::BytesMalformed("Checksum miss match".to_string()));
    }
    println!("recvvvvv ok");
    Ok(())
}

async fn decode(buf: &mut BufReader<BidirectionalStream>) -> Result<Self> {
    // path
    let path_len = buf.read_u16().await? as usize;
    let mut path_bytes = Vec::from_iter(std::iter::repeat(0u8).take(path_len));
    buf.read_exact(&mut path_bytes).await?;
    let path = PathBuf::from(String::from_utf8(path_bytes.to_vec())?);
    // is dir
    let is_dir = buf.read_u8().await? == 1;
    if is_dir {
        return Ok(Self {
            path,
            is_dir,
            permission: 0,
            file_size: 0,
        });
    }

    // permission
    let permission = buf.read_u32().await?;
    // file size
    let file_size = buf.read_u64().await?;

    Ok(Self {
        path,
        is_dir,
        permission,
        file_size,
    })
}

pub async fn handle_send(mut stream: BidirectionalStream, path: PathBuf) -> Result<()> {
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
    let chunks = if file_size == 0 {
        0
    } else {
        (file_size / (FRAME_SIZE as u64) + 1) as u16
    };
    buf.put_u16(chunks);
    // first send, file metadata
    stream.send(buf.freeze()).await?;

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
        println!("send file content chunk!!! {}", read);
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
    // third send, file size and checksum
    stream.send(buf.freeze()).await?;

    // wait for reply
    println!("waittttt");
    let mut buf = stream.receive().await?.ok_or(Error::StreamClosed)?;
    println!("waittttt 1");
    assert_reply(&mut buf)?;
    Ok(())
}
