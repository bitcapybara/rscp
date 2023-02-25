use std::{fmt::Display, io, net::SocketAddr};

use s2n_quic::provider::{self, tls::rustls::rustls};

use crate::mtls::MtlsProvider;

type Result<T> = std::result::Result<T, ServerError>;

#[derive(Debug)]
pub enum ServerError {
    Io(String),
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
        while let Some(mut conn) = self.server.accept().await {
            let stream = conn.accept_bidirectional_stream().await;
            todo!()
        }

        Ok(())
    }
}
