use std::{fs, future::Future, net::SocketAddr, path::PathBuf};

use anyhow::bail;
use clap::{arg, Parser};
use flexi_logger::Logger;
use librscp::{
    endpoint::{Action, Endpoint, Error, PathTuple},
    mtls::MtlsProvider,
};
use log::info;

#[derive(Debug, Parser)]
pub struct Opt {
    /// log level
    #[arg(long = "log_level", required = false, env = "RSCP_LOG_LEVEL")]
    log_level: String,
    /// Start as a server
    #[arg(short = 's')]
    server: bool,
    /// Serve port (for server) or remote port (for client)
    #[arg(short = 'p', env = "RSCP_PORT")]
    port: u16,
    /// Directory include ca pem files   
    #[arg(short = 'c', env = "RSCP_CA_DIR")]
    ca_path: PathBuf,
    /// Source path
    #[arg(required = false, required_unless_present = "server")]
    source: String,
    /// Target path
    #[arg(required = false, required_unless_present = "server")]
    target: String,
}

fn main() -> anyhow::Result<()> {
    let opts = Opt::parse();
    // log init
    Logger::try_with_str(opts.log_level)?
        .log_to_stdout()
        .start()?;
    info!("logger init done");
    // ca
    let ca_path = &opts.ca_path;
    let (ca, cert, key) = if opts.server {
        (
            fs::read(ca_path.join("ca.pem"))?,
            fs::read(ca_path.join("server.pem"))?,
            fs::read(ca_path.join("server-key.pem"))?,
        )
    } else {
        (
            fs::read(ca_path.join("ca.pem"))?,
            fs::read(ca_path.join("client.pem"))?,
            fs::read(ca_path.join("client-key.pem"))?,
        )
    };

    // build endpoint
    let provider = MtlsProvider::new(&ca, &cert, &key)?;
    if opts.server {
        let addr = SocketAddr::new("0.0.0.0".parse()?, opts.port);
        info!("server start at {}", opts.port);
        run(Endpoint::new(provider, addr)?.start_server())?;
    } else {
        let (source, target) = (opts.source, opts.target);
        let (remote_addr, action) = match (source.split_once(':'), target.split_once(':')) {
            (Some((remote_ip, remote_path)), None) => (
                SocketAddr::new(remote_ip.parse()?, opts.port),
                Action::Get(PathTuple {
                    local: PathBuf::from(target),
                    remote: PathBuf::from(remote_path),
                }),
            ),
            (None, Some((remote_ip, remote_path))) => (
                SocketAddr::new(remote_ip.parse()?, opts.port),
                Action::Post(PathTuple {
                    local: PathBuf::from(source),
                    remote: PathBuf::from(remote_path),
                }),
            ),
            _ => bail!("Unexpect source/target path"),
        };
        info!("client start");
        run(Endpoint::new(provider, remote_addr)?.start_client(action))?;
    }

    Ok(())
}

#[tokio::main]
async fn run(fut: impl Future<Output = Result<(), Error>>) -> anyhow::Result<()> {
    Ok(fut.await?)
}
