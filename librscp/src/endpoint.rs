use std::{io, net::SocketAddr, path::PathBuf};

use futures::FutureExt;
use log::error;
use s2n_quic::{
    client::Connect,
    connection,
    provider::{self, tls::rustls::rustls},
    Connection,
};
use tokio::fs;
use url::Url;

use crate::{
    mtls::MtlsProvider,
    protocol::{self, Method, ProtocolStream},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid URL: {0}")]
    Url(String),
    #[error("TLS auth error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Endpoint start up error: {0}")]
    StartUp(String),
    #[error("QUIC connection error: {0}")]
    Connection(#[from] connection::Error),
    #[error("Protocol codec error: {0}")]
    Protocol(#[from] protocol::Error),
}

impl From<provider::StartError> for Error {
    fn from(e: provider::StartError) -> Self {
        Error::StartUp(e.to_string())
    }
}

pub enum Action {
    /// rscp remote:/path /path
    Get { remote: Url, tuple: PathTuple },
    /// rscp /path remote:/path
    Post { remote: Url, tuple: PathTuple },
}

pub struct PathTuple {
    pub local: PathBuf,
    pub remote: PathBuf,
}

pub async fn start_server(provider: MtlsProvider, addr: SocketAddr) -> Result<()> {
    let mut server = s2n_quic::Server::builder()
        .with_tls(provider)
        .unwrap()
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
    let Some(bi_stream) = conn.accept_bidirectional_stream().await? else {
        error!("QUIC connection closed");
        return Ok(());
    };

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
                remote: remote_url,
                tuple: PathTuple { local, remote },
            } => {
                // build connection
                let mut conn = new_connector(provider.clone(), remote_url).await?;
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

async fn new_connector(provider: MtlsProvider, remote_url: Url) -> Result<Connection> {
    let socket_addr = remote_url
        .socket_addrs(|| None)?
        .first()
        .cloned()
        .ok_or(Error::Url("Socket addr of url not found".to_string()))?;
    let server_name = remote_url
        .domain()
        .ok_or(Error::Url("Domain of url not found".to_string()))?;
    let client: s2n_quic::Client = s2n_quic::Client::builder()
        .with_tls(provider)
        .unwrap()
        .with_io("0.0.0.0:0")?
        .start()?;
    let connect = Connect::new(socket_addr).with_server_name(server_name);
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
