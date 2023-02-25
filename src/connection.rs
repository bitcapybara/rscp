use s2n_quic::{connection, Connection};
use std::{fmt::Display, path::PathBuf};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl From<connection::Error> for Error {
    fn from(value: connection::Error) -> Self {
        todo!()
    }
}

pub async fn send_ok(conn: &mut Connection) -> Result<()> {
    Ok(())
}

pub async fn send_err(conn: &mut Connection, msg: &str) -> Result<()> {
    Ok(())
}

pub async fn recv_file(conn: &mut Connection, path: PathBuf) -> Result<()> {
    // stream per received file
    while let Some(stream) = conn.accept_receive_stream().await? {
        todo!()
    }
    Ok(())
}

pub async fn send_file(conn: &mut Connection, path: PathBuf) -> Result<()> {
    // stream per send file
    let stream = conn.open_send_stream().await?;
    Ok(())
}
