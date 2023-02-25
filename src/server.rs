use std::{fmt::Display, io, net::SocketAddr};

use s2n_quic::{
    connection,
    provider::{self, tls::rustls::rustls},
    stream,
};

use crate::mtls::MtlsProvider;

type Result<T> = std::result::Result<T, ServerError>;

#[derive(Debug)]
pub enum ServerError {
    Io(String),
    Stopped,
    MissHandsake,
}

impl std::error::Error for ServerError {}

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl From<io::Error> for ServerError {
    fn from(value: io::Error) -> Self {
        todo!()
    }
}

impl From<rustls::Error> for ServerError {
    fn from(value: rustls::Error) -> Self {
        todo!()
    }
}

impl From<provider::StartError> for ServerError {
    fn from(value: provider::StartError) -> Self {
        todo!()
    }
}

impl From<std::convert::Infallible> for ServerError {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl From<connection::Error> for ServerError {
    fn from(value: connection::Error) -> Self {
        todo!()
    }
}

impl From<stream::Error> for ServerError {
    fn from(value: stream::Error) -> Self {
        todo!()
    }
}

pub struct Server {
    server: s2n_quic::Server,
}

impl Server {
    pub fn new(provider: MtlsProvider, addr: SocketAddr) -> Result<Self> {
        let server = s2n_quic::Server::builder()
            .with_tls(provider)?
            .with_io(addr)?
            .start()?;
        Ok(Self { server })
    }

    pub async fn start(mut self) -> Result<()> {
        // conn per client
        while let Some(mut conn) = self.server.accept().await {
            // first recv a message
            let mut peer = conn.accept().await?.ok_or(ServerError::Stopped)?;
            let handshake = peer.receive().await?.ok_or(ServerError::MissHandsake)?;
            // stream per received file
            while let Some(stream) = conn.accept_receive_stream().await? {
                todo!()
            }
            // stream per send file
            let stream = conn.open_send_stream().await?;
            todo!()
        }

        Ok(())
    }
}
