use std::{fmt::Display, io, net::SocketAddr, path::PathBuf};

use futures::FutureExt;
use log::error;
use s2n_quic::{
    client::Connect,
    connection,
    provider::{self, tls::rustls::rustls},
    Connection,
};
use tokio::fs;

use crate::{
    mtls::MtlsProvider,
    protocol::{self, Method, ProtocolStream},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// io error
    Io(io::Error),
    /// QUIC connection closed
    ConnClosed,
    /// TLS error
    Tls(rustls::Error),
    /// start up error
    StartUp(String),
    /// QUIC connection error
    Connection(connection::Error),
    /// protocol codec error
    Protocol(protocol::Error),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::ConnClosed => write!(f, "QUIC connection already closed"),
            Error::Tls(e) => write!(f, "TLS auth error: {e}"),
            Error::StartUp(s) => write!(f, "Endpoint start up error: {s}"),
            Error::Connection(e) => write!(f, "QUIC connection error: {e}"),
            Error::Protocol(e) => write!(f, "Protocol parse error: {e}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e)
    }
}

impl From<provider::StartError> for Error {
    fn from(e: provider::StartError) -> Self {
        Error::StartUp(e.to_string())
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl From<connection::Error> for Error {
    fn from(e: connection::Error) -> Self {
        Error::Connection(e)
    }
}

impl From<protocol::Error> for Error {
    fn from(e: protocol::Error) -> Self {
        Error::Protocol(e)
    }
}

pub enum Action {
    /// rscp remote:/path /path
    Get {
        remote: SocketAddr,
        tuple: PathTuple,
    },
    /// rscp /path remote:/path
    Post {
        remote: SocketAddr,
        tuple: PathTuple,
    },
}

pub struct PathTuple {
    pub local: PathBuf,
    pub remote: PathBuf,
}

pub async fn start_server(provider: MtlsProvider, addr: SocketAddr) -> Result<()> {
    let mut server = s2n_quic::Server::builder()
        .with_tls(provider)?
        .with_io(addr)?
        .start()?;
    // conn per client
    while let Some(conn) = server.accept().await {
        // handle connection from client
        let local = conn.local_addr()?;
        let fut = handle_conn(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("handle connection from client error: {e}, client addr: {local}");
            }
        });
    }

    Ok(())
}

async fn handle_conn(mut conn: Connection) -> Result<()> {
    // first recv handshake message
    let bi_stream = conn
        .accept_bidirectional_stream()
        .await?
        .ok_or(Error::ConnClosed)?;
    let mut stream = ProtocolStream::new(bi_stream);
    match stream.method_recv().await {
        Ok(action) => match action {
            Method::Get(path) => handle_send_file(&mut conn, path).await?,
            Method::Post(path) => handle_recv_file(&mut conn, path).await?,
        },
        Err(e) => {
            error!("Decode Method error: {e}")
        }
    }
    Ok(())
}

pub async fn start_client(provider: MtlsProvider, actions: Vec<Action>) -> Result<()> {
    for action in actions {
        match action {
            Action::Get {
                remote: remote_addr,
                tuple: PathTuple { local, remote },
            } => {
                // build connection
                let mut conn = new_connector(provider.clone(), remote_addr).await?;
                // send method to server
                let bi_stream = conn.open_bidirectional_stream().await?;
                let mut stream = ProtocolStream::new(bi_stream);
                // send get message
                stream.method_send(Method::Get(remote)).await?;
                // recv files
                handle_recv_file(&mut conn, local.clone()).await?;
            }
            Action::Post {
                remote: remote_addr,
                tuple: PathTuple { local, remote },
            } => {
                // build connection
                let mut conn = new_connector(provider.clone(), remote_addr).await?;
                // send method to server
                let bi_stream = conn.open_bidirectional_stream().await?;
                let mut stream = ProtocolStream::new(bi_stream);
                // send post message
                stream.method_send(Method::Post(remote)).await?;
                // send files
                handle_send_file(&mut conn, local).await?;
            }
        }
    }
    Ok(())
}

async fn new_connector(provider: MtlsProvider, remote_addr: SocketAddr) -> Result<Connection> {
    let client: s2n_quic::Client = s2n_quic::Client::builder()
        .with_tls(provider)?
        .with_io("0.0.0.0:0")?
        .start()?;
    let connect = Connect::new(remote_addr).with_server_name("localhost");
    Ok(client.connect(connect).await?)
}

async fn handle_recv_file(conn: &mut Connection, path: PathBuf) -> Result<()> {
    // recv files
    let mut futs = Vec::new();
    while let Ok(Some(bi_stream)) = conn.accept_bidirectional_stream().await {
        let stream = ProtocolStream::new(bi_stream);
        let (task, handle) = stream.handle_file_recv(path.clone()).remote_handle();
        tokio::spawn(task);
        futs.push((path.clone(), handle));
    }
    for (path, fut) in futs {
        if let Err(e) = fut.await {
            error!("Get {} error: {e}", path.display())
        }
    }
    Ok(())
}

async fn handle_send_file(conn: &mut Connection, path: PathBuf) -> Result<()> {
    // send files under path to client
    let paths = list_all_files(path).await?;
    let mut futs = Vec::with_capacity(paths.len());
    for path in paths {
        // coroutine per file
        let bi_stream = conn.open_bidirectional_stream().await?;
        let stream = ProtocolStream::new(bi_stream);
        let (task, handle) = stream.handle_file_send(path.clone()).remote_handle();
        tokio::spawn(task);
        futs.push((path, handle));
    }
    for (path, fut) in futs {
        if let Err(e) = fut.await {
            error!("Post {} error: {e}", path.display())
        }
    }
    Ok(())
}

// list all files/emptydir under path
async fn list_all_files(path: PathBuf) -> Result<Vec<PathBuf>> {
    let path = fs::canonicalize(path).await?;
    if !path.exists() {
        return Err(io::Error::from(io::ErrorKind::NotFound))?;
    }
    let mut entries = vec![path];
    let mut res = Vec::new();
    while let Some(entry) = entries.pop() {
        // return file
        if entry.is_file() {
            res.push(entry);
            continue;
        }

        let mut read_dir = entry.read_dir()?.peekable();
        // return empty dir
        if read_dir.peek().is_none() {
            res.push(entry);
            continue;
        }
        // dir content
        for child in read_dir {
            let child = child?.path();
            entries.push(child);
        }
    }
    Ok(res)
}
