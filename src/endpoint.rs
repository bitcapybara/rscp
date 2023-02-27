use std::{fmt::Display, io, net::SocketAddr, path::PathBuf};

use log::error;
use s2n_quic::{
    client::Connect,
    connection,
    provider::{self, tls::rustls::rustls},
    stream, Connection,
};

use crate::{
    mtls::MtlsProvider,
    protocol::{self, Action},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(String),
    Stopped,
    MissHandsake,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        todo!()
    }
}

impl From<rustls::Error> for Error {
    fn from(value: rustls::Error) -> Self {
        todo!()
    }
}

impl From<provider::StartError> for Error {
    fn from(value: provider::StartError) -> Self {
        todo!()
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl From<connection::Error> for Error {
    fn from(value: connection::Error) -> Self {
        todo!()
    }
}

impl From<stream::Error> for Error {
    fn from(value: stream::Error) -> Self {
        todo!()
    }
}

impl From<protocol::Error> for Error {
    fn from(value: protocol::Error) -> Self {
        todo!()
    }
}

pub struct Endpoint {
    provider: MtlsProvider,
    addr: SocketAddr,
}

impl Endpoint {
    pub fn new(provider: MtlsProvider, addr: SocketAddr) -> Result<Self> {
        Ok(Self { provider, addr })
    }

    pub async fn start_server(self) -> Result<()> {
        let mut server = s2n_quic::Server::builder()
            .with_tls(self.provider)?
            .with_io(self.addr)?
            .start()?;
        // conn per client
        while let Some(conn) = server.accept().await {
            // handle connection from client
            let local = conn.local_addr()?;
            let fut = Self::handle_conn(conn);
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
        let mut stream = conn
            .accept_bidirectional_stream()
            .await?
            .ok_or(Error::Stopped)?;
        match Action::decode(&mut stream).await? {
            Action::Get => protocol::File::handle_send(&mut stream, &PathBuf::from("")).await?,
            Action::Post => protocol::File::handle_recv(&mut stream).await?,
        }
        Ok(())
    }

    pub async fn start_client(self) -> Result<()> {
        let client: s2n_quic::Client = s2n_quic::Client::builder()
            .with_tls(self.provider)?
            .with_io("0.0.0.0:0")?
            .start()?;

        let connect = Connect::new(self.addr).with_server_name("localhost");
        let mut conn = client.connect(connect).await?;
        // stream per received file
        while let Some(stream) = conn.accept_receive_stream().await? {
            todo!()
        }
        // stream per send file
        let stream = conn.open_send_stream().await?;
        Ok(())
    }
}
