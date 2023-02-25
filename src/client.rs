use std::{fmt::Display, io, net::SocketAddr};

use s2n_quic::{client::Connect, connection, provider, Connection};

use crate::mtls::MtlsProvider;

type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug)]
pub enum ClientError {}

impl std::error::Error for ClientError {}

impl Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl From<io::Error> for ClientError {
    fn from(value: io::Error) -> Self {
        todo!()
    }
}

impl From<std::convert::Infallible> for ClientError {
    fn from(value: std::convert::Infallible) -> Self {
        todo!()
    }
}

impl From<provider::StartError> for ClientError {
    fn from(value: provider::StartError) -> Self {
        todo!()
    }
}

impl From<connection::Error> for ClientError {
    fn from(value: connection::Error) -> Self {
        todo!()
    }
}

pub struct Client {
    conn: Connection,
}

impl Client {
    pub async fn new(provider: MtlsProvider, remote: SocketAddr) -> Result<Self> {
        let client: s2n_quic::Client = s2n_quic::Client::builder()
            .with_tls(provider)?
            .with_io("0.0.0.0:0")?
            .start()?;
        let connect = Connect::new(remote).with_server_name("localhost");
        let conn = client.connect(connect).await?;

        Ok(Self { conn })
    }
}
