use std::{fs, future::Future, path::PathBuf};

use anyhow::bail;
use clap::{arg, Parser};
use flexi_logger::{colored_detailed_format, Logger};
use librscp::{
    endpoint::{start_client, start_server, Action, Error, PathTuple},
    mtls::MtlsProvider,
};
use log::info;

#[derive(Debug, Parser)]
pub struct Opt {
    /// log level
    #[arg(long = "log_level", default_value = "info", env = "RSCP_LOG_LEVEL")]
    log_level: String,
    /// Start as a server
    #[arg(long)]
    server: bool,
    /// ip addr
    #[arg(long, short, default_value = "0.0.0.0", env = "RSCP_SERVER_IP")]
    ip: String,
    /// Serve port (for server) or remote port (for client)
    #[arg(short, default_value = "3322", env = "RSCP_SERVER_PORT")]
    port: u16,
    /// Directory include ca pem files   
    #[arg(short, default_value = "./certs", env = "RSCP_CA_DIR")]
    ca_path: PathBuf,
    /// Source path
    #[arg(short, long, required = false, value_delimiter = ',')]
    source: Vec<String>,
    /// Target path
    #[arg(short, long, required = false, value_delimiter = ',')]
    target: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    // cli command args
    let opts = Opt::parse();
    // log init
    Logger::try_with_str(opts.log_level)
        .unwrap()
        .format(colored_detailed_format)
        .start()
        .unwrap();
    info!("logger init done");
    // ca
    let ca_path = &opts.ca_path;
    let (ca_file, cert_file, key_file) = if opts.server {
        ("ca-cert.pem", "server-cert.pem", "server-key.pem")
    } else {
        ("ca-cert.pem", "client-cert.pem", "client-key.pem")
    };
    let (ca, cert, key) = (
        fs::read(ca_path.join(ca_file))?,
        fs::read(ca_path.join(cert_file))?,
        fs::read(ca_path.join(key_file))?,
    );
    let provider = MtlsProvider::new(&ca, &cert, &key)?;

    // build endpoint
    if opts.server {
        let addr = format!("{}:{}", opts.ip, opts.port).parse()?;
        info!("server start at {}", opts.port);
        run(start_server(provider, addr))?;
    } else {
        let (source, target) = (opts.source, opts.target);
        let mut actions = Vec::new();
        match (source.len(), target.len()) {
            (1, 2..) => {
                let source_path = &source[0];
                for target_path in &target {
                    let action = build_actions(source_path, target_path, opts.port)?;
                    actions.push(action)
                }
            }
            (2.., 1) => {
                let target_path = &target[0];
                for source_path in &source {
                    let action = build_actions(source_path, target_path, opts.port)?;
                    actions.push(action)
                }
            }
            (a @ 1.., b @ 1..) if a == b => {
                for i in 0..a {
                    let source_path = &source[i];
                    let target_path = &target[i];
                    let action = build_actions(source_path, target_path, opts.port)?;
                    actions.push(action)
                }
            }
            _ => bail!("incorrect source/target path numbers"),
        }
        info!("client start");
        run(start_client(provider, actions))?;
    }

    Ok(())
}

fn build_actions(source_path: &str, target_path: &str, port: u16) -> anyhow::Result<Action> {
    let action = match (source_path.split_once(':'), target_path.split_once(':')) {
        (Some((remote_url, remote_path)), None) => Action::Get {
            remote: format!("rscp://{}:{}", remote_url, port).parse()?,
            tuple: PathTuple {
                local: PathBuf::from(target_path),
                remote: PathBuf::from(remote_path),
            },
        },
        (None, Some((remote_url, remote_path))) => Action::Post {
            remote: format!("resp://{}:{}", remote_url, port).parse()?,
            tuple: PathTuple {
                local: PathBuf::from(source_path),
                remote: PathBuf::from(remote_path),
            },
        },
        _ => bail!("Unexpect source/target path"),
    };
    Ok(action)
}

#[tokio::main]
async fn run<F>(fut: F) -> anyhow::Result<()>
where
    F: Future<Output = Result<(), Error>>,
{
    Ok(fut.await?)
}
