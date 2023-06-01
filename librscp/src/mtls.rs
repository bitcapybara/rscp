use std::io::Cursor;

use s2n_quic::provider::tls::{
    self,
    rustls::{rustls, Client, Server},
};

static PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

static DEFAULT_CIPHERSUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

#[derive(Clone)]
pub struct MtlsProvider {
    root_store: rustls::RootCertStore,
    cert_chain: Vec<rustls::Certificate>,
    private_key: rustls::PrivateKey,
}

impl tls::Provider for MtlsProvider {
    type Server = Server;

    type Client = Client;

    type Error = rustls::Error;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        let verifier = rustls::server::AllowAnyAuthenticatedClient::new(self.root_store);
        let mut cfg = rustls::ServerConfig::builder()
            .with_cipher_suites(DEFAULT_CIPHERSUITES)
            .with_safe_default_kx_groups()
            .with_protocol_versions(PROTOCOL_VERSIONS)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.cert_chain, self.private_key)?;
        cfg.ignore_client_order = true;
        cfg.alpn_protocols = vec![b"h3".to_vec()];
        Ok(cfg.into())
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        let mut cfg = rustls::ClientConfig::builder()
            .with_cipher_suites(DEFAULT_CIPHERSUITES)
            .with_safe_default_kx_groups()
            .with_protocol_versions(PROTOCOL_VERSIONS)?
            .with_root_certificates(self.root_store)
            .with_single_cert(self.cert_chain, self.private_key)?;
        cfg.alpn_protocols = vec![b"h3".to_vec()];
        Ok(cfg.into())
    }
}

impl MtlsProvider {
    pub fn new(ca_cert: &[u8], cert: &[u8], key: &[u8]) -> Result<Self, rustls::Error> {
        let root_store = into_root_store(ca_cert)?;
        let cert_chain = into_certificate(cert)?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let private_key = rustls::PrivateKey(into_private_key(key)?);
        Ok(MtlsProvider {
            root_store,
            cert_chain,
            private_key,
        })
    }
}

fn into_certificate(mut cert: &[u8]) -> Result<Vec<Vec<u8>>, rustls::Error> {
    let certs = rustls_pemfile::certs(&mut cert)
        .map(|certs| certs.into_iter().collect())
        .map_err(|_| rustls::Error::General("Could not read certificate".to_string()))?;
    Ok(certs)
}

fn into_root_store(cert: &[u8]) -> Result<rustls::RootCertStore, rustls::Error> {
    let ca_cert = into_certificate(cert)?;
    let mut cert_store = rustls::RootCertStore::empty();
    cert_store.add_parsable_certificates(ca_cert.as_slice());
    Ok(cert_store)
}

fn into_private_key(key: &[u8]) -> Result<Vec<u8>, rustls::Error> {
    let mut cursor = Cursor::new(key);
    let parsers = [
        rustls_pemfile::rsa_private_keys,
        rustls_pemfile::pkcs8_private_keys,
    ];
    for parser in parsers {
        cursor.set_position(0);
        match parser(&mut cursor) {
            Ok(keys) if keys.is_empty() => continue,
            Ok(mut keys) if keys.len() == 1 => return Ok(rustls::PrivateKey(keys.pop().unwrap()).0),
            Ok(keys) => {
                return Err(rustls::Error::General(format!(
                    "Unexpected number of keys: {} (only 1 supported)",
                    keys.len()
                )));
            }
            Err(_) => continue,
        }
    }
    Err(rustls::Error::General(
        "could not load any valid private keys".to_string(),
    ))
}
