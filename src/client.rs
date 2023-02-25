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
    client: s2n_quic::Client,
    connect: Connect,
}

impl Client {
    pub fn new(provider: MtlsProvider, remote: SocketAddr) -> Result<Self> {
        let client: s2n_quic::Client = s2n_quic::Client::builder()
            .with_tls(provider)?
            .with_io("0.0.0.0:0")?
            .start()?;

        let connect = Connect::new(remote).with_server_name("localhost");
        Ok(Self { client, connect })
    }

    pub async fn start(mut self) -> Result<()> {
        let mut conn = self.client.connect(self.connect).await?;
        // stream per received file
        while let Some(stream) = conn.accept_receive_stream().await? {
            todo!()
        }
        // stream per send file
        let stream = conn.open_send_stream().await?;
        Ok(())
    }
}
