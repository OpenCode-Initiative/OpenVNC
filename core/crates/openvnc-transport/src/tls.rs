//! TLS 1.3 (rustls, provider `ring`).
//!
//! Tres modos de confianca no cliente, sempre explicitos:
//!
//! - [`Trust::WebPki`]: cadeia validada contra as raizes Mozilla (e CAs
//!   extras) e nome do host conferido. E o padrao.
//! - [`Trust::Pinned`]: o certificado do servidor tem que ter exatamente
//!   este SHA-256 (auto-assinados, pinning manual).
//! - [`Trust::Tofu`]: *trust on first use* com arquivo `known_hosts`. Um
//!   host desconhecido so e aceito com `accept_new`; um fingerprint
//!   diferente do gravado e **sempre** erro (nunca sobrescreve sozinho).
//!
//! Em todos os modos a assinatura do handshake e verificada com a chave do
//! certificado, entao o servidor prova que possui a chave privada.
//! So TLS 1.3 e negociado.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use openvnc_core::{Error, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};

pub use tokio_rustls::{
    client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor,
};

fn tls_err(e: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("tls: {e}"))
}

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// SHA-256 do certificado (DER) em hex minusculo separado por `:`.
pub fn fingerprint(cert_der: &[u8]) -> String {
    let d = Sha256::digest(cert_der);
    d.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Normaliza um fingerprint digitado (aceita com ou sem `:`, maiusculas).
pub fn normalize_fingerprint(s: &str) -> Result<String> {
    let hex: String = s
        .trim()
        .trim_start_matches("sha256:")
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Protocol(
            "fingerprint SHA-256 invalido (esperado 32 bytes em hex)".into(),
        ));
    }
    Ok(hex
        .as_bytes()
        .chunks(2)
        .map(|p| std::str::from_utf8(p).expect("ascii"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Arquivo `known_hosts`: uma linha `host:porta fingerprint` por servidor.
#[derive(Debug, Clone)]
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    /// Usa o arquivo `path` (criado na primeira gravacao).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        KnownHosts { path: path.into() }
    }

    /// Caminho padrao: `$OPENVNC_KNOWN_HOSTS`, senao
    /// `~/.config/openvnc/known_hosts` (`%APPDATA%\openvnc\known_hosts`).
    pub fn default_path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("OPENVNC_KNOWN_HOSTS") {
            return Some(p.into());
        }
        let base = if cfg!(windows) {
            std::env::var_os("APPDATA").map(PathBuf::from)
        } else {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
        };
        base.map(|b| b.join("openvnc").join("known_hosts"))
    }

    /// Caminho do arquivo.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Fingerprint gravado para `host`.
    pub fn get(&self, host: &str) -> Result<Option<String>> {
        let f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        for line in std::io::BufReader::new(f).lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((h, fp)) = line.split_once(char::is_whitespace) {
                if h == host {
                    return Ok(Some(normalize_fingerprint(fp)?));
                }
            }
        }
        Ok(None)
    }

    /// Grava `host` (falha se ja houver outro fingerprint para ele).
    pub fn add(&self, host: &str, fp: &str) -> Result<()> {
        let fp = normalize_fingerprint(fp)?;
        match self.get(host)? {
            Some(old) if old == fp => return Ok(()),
            Some(_) => {
                return Err(Error::Protocol(format!(
                    "{host} ja tem outro fingerprint em {}; remova a linha manualmente",
                    self.path.display()
                )))
            }
            None => {}
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{host} {fp}")?;
        Ok(())
    }
}

/// Politica de confianca do cliente.
#[derive(Debug, Clone)]
pub enum Trust {
    /// Raizes Mozilla (webpki-roots) mais CAs extras em PEM.
    WebPki {
        /// Certificados de CA adicionais (DER).
        extra_roots: Vec<CertificateDer<'static>>,
    },
    /// Fingerprint SHA-256 fixo.
    Pinned(String),
    /// Trust on first use.
    Tofu {
        /// Arquivo de hosts conhecidos.
        store: KnownHosts,
        /// Aceitar (e gravar) um host ainda desconhecido.
        accept_new: bool,
    },
}

impl Default for Trust {
    fn default() -> Self {
        Trust::WebPki {
            extra_roots: Vec::new(),
        }
    }
}

/// Configuracao TLS do cliente.
#[derive(Debug, Clone, Default)]
pub struct ClientTls {
    /// Politica de confianca.
    pub trust: Trust,
}

impl ClientTls {
    /// Monta a configuracao rustls. `host_key` identifica o servidor no
    /// `known_hosts` (normalmente `host:porta`).
    pub fn rustls_config(
        &self,
        host_key: &str,
        alpn: &[&[u8]],
    ) -> Result<(Arc<rustls::ClientConfig>, Observed)> {
        let observed = Observed::default();
        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_err)?;
        let mut cfg = match &self.trust {
            Trust::WebPki { extra_roots } => {
                let mut roots = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                for c in extra_roots {
                    roots.add(c.clone()).map_err(tls_err)?;
                }
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            Trust::Pinned(fp) => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinVerifier {
                    mode: PinMode::Fixed(normalize_fingerprint(fp)?),
                    observed: observed.clone(),
                }))
                .with_no_client_auth(),
            Trust::Tofu { store, accept_new } => {
                let mode = match store.get(host_key)? {
                    Some(fp) => PinMode::Fixed(fp),
                    None if *accept_new => PinMode::AcceptAny,
                    None => PinMode::RejectUnknown {
                        host: host_key.to_string(),
                    },
                };
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinVerifier {
                        mode,
                        observed: observed.clone(),
                    }))
                    .with_no_client_auth()
            }
        };
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        Ok((Arc::new(cfg), observed))
    }

    /// Depois de um handshake bem-sucedido em modo TOFU, grava o host novo.
    pub fn commit(&self, host_key: &str, observed: &Observed) -> Result<()> {
        if let (Trust::Tofu { store, .. }, Some(fp)) = (&self.trust, observed.get()) {
            if store.get(host_key)?.is_none() {
                tracing::warn!(host = host_key, fingerprint = %fp, "TOFU: novo host gravado");
                store.add(host_key, &fp)?;
            }
        }
        Ok(())
    }

    /// Faz o handshake TLS sobre `stream`.
    pub async fn connect<S>(
        &self,
        stream: S,
        server_name: &str,
        host_key: &str,
    ) -> Result<ClientTlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (cfg, observed) = self.rustls_config(host_key, &[])?;
        let name = server_name_of(server_name)?;
        let s = tokio_rustls::TlsConnector::from(cfg)
            .connect(name, stream)
            .await
            .map_err(|e| {
                // erros do verificador vem como InvalidData com a mensagem
                Error::Protocol(format!("tls: handshake falhou: {e}"))
            })?;
        self.commit(host_key, &observed)?;
        Ok(s)
    }
}

/// Converte host em `ServerName` (DNS ou IP).
pub fn server_name_of(host: &str) -> Result<ServerName<'static>> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(h.to_string()).map_err(|_| tls_err(format!("nome invalido: {host}")))
}

/// Separa `host:porta` em host (sem colchetes).
pub fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
}

/// Fingerprint visto no ultimo handshake.
#[derive(Debug, Clone, Default)]
pub struct Observed(Arc<Mutex<Option<String>>>);

impl Observed {
    /// Fingerprint observado.
    pub fn get(&self) -> Option<String> {
        self.0.lock().expect("mutex").clone()
    }
}

#[derive(Debug)]
enum PinMode {
    Fixed(String),
    AcceptAny,
    RejectUnknown { host: String },
}

#[derive(Debug)]
struct PinVerifier {
    mode: PinMode,
    observed: Observed,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity);
        *self.observed.0.lock().expect("mutex") = Some(fp.clone());
        match &self.mode {
            PinMode::Fixed(want) if *want == fp => Ok(ServerCertVerified::assertion()),
            PinMode::Fixed(want) => Err(rustls::Error::General(format!(
                "CERTIFICADO MUDOU: esperado {want}, recebido {fp}"
            ))),
            PinMode::AcceptAny => Ok(ServerCertVerified::assertion()),
            PinMode::RejectUnknown { host } => Err(rustls::Error::General(format!(
                "host desconhecido {host} (fingerprint {fp}); confira e aceite explicitamente"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Le certificados PEM.
pub fn load_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let v = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(tls_err)?;
    if v.is_empty() {
        return Err(tls_err("nenhum certificado no PEM"));
    }
    Ok(v)
}

/// Identidade do servidor: cadeia de certificados e chave privada.
#[derive(Debug)]
pub struct ServerIdentity {
    /// Cadeia (o primeiro e o certificado do servidor).
    pub certs: Vec<CertificateDer<'static>>,
    /// Chave privada.
    pub key: PrivateKeyDer<'static>,
}

impl Clone for ServerIdentity {
    fn clone(&self) -> Self {
        ServerIdentity {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl ServerIdentity {
    /// Le cadeia e chave PEM.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let certs = load_certs(cert_pem)?;
        use rustls::pki_types::pem::PemObject;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|e| tls_err(format!("chave privada PEM: {e}")))?;
        Ok(ServerIdentity { certs, key })
    }

    /// Gera um certificado auto-assinado (ECDSA P-256) para `names`.
    pub fn self_signed(names: &[String]) -> Result<Self> {
        let ck = rcgen::generate_simple_self_signed(names.to_vec()).map_err(tls_err)?;
        let key = PrivateKeyDer::try_from(ck.key_pair.serialize_der()).map_err(tls_err)?;
        Ok(ServerIdentity {
            certs: vec![ck.cert.der().clone()],
            key,
        })
    }

    /// Le `cert`/`key` de disco; se nao existirem, gera auto-assinado e
    /// grava (a chave com permissao restrita onde o SO permitir).
    pub fn load_or_create(cert: &Path, key: &Path, names: &[String]) -> Result<Self> {
        if cert.exists() && key.exists() {
            return Self::from_pem(&std::fs::read(cert)?, &std::fs::read(key)?);
        }
        let ck = rcgen::generate_simple_self_signed(names.to_vec()).map_err(tls_err)?;
        for p in [cert, key] {
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d)?;
            }
        }
        std::fs::write(cert, ck.cert.pem())?;
        write_private(key, ck.key_pair.serialize_pem().as_bytes())?;
        Self::from_pem(&std::fs::read(cert)?, &std::fs::read(key)?)
    }

    /// Fingerprint do certificado do servidor.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.certs[0])
    }

    /// Configuracao rustls (TLS 1.3, sem autenticacao de cliente).
    pub fn rustls_config(&self, alpn: &[&[u8]]) -> Result<Arc<rustls::ServerConfig>> {
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_err)?
            .with_no_client_auth()
            .with_single_cert(self.certs.clone(), self.key.clone_key())
            .map_err(tls_err)?;
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        Ok(Arc::new(cfg))
    }

    /// Acceptor tokio.
    pub fn acceptor(&self) -> Result<tokio_rustls::TlsAcceptor> {
        Ok(tokio_rustls::TlsAcceptor::from(self.rustls_config(&[])?))
    }
}

#[cfg(unix)]
fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(p, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair(id: &ServerIdentity, tls: &ClientTls, host_key: &str) -> Result<Vec<u8>> {
        let (a, b) = tokio::io::duplex(1 << 16);
        let acc = id.acceptor()?;
        let srv = tokio::spawn(async move {
            if let Ok(mut s) = acc.accept(b).await {
                let _ = s.write_all(b"ola").await;
                let _ = s.flush().await;
                let _ = s.shutdown().await;
            }
        });
        let res = async {
            let mut c = tls.connect(a, "localhost", host_key).await?;
            let mut v = Vec::new();
            c.read_to_end(&mut v).await?;
            Ok(v)
        }
        .await;
        let _ = srv.await;
        res
    }

    #[test]
    fn fingerprint_normalization() {
        let fp = fingerprint(b"x");
        assert_eq!(normalize_fingerprint(&fp.to_uppercase()).unwrap(), fp);
        assert_eq!(normalize_fingerprint(&fp.replace(':', "")).unwrap(), fp);
        assert!(normalize_fingerprint("abc").is_err());
        assert_eq!(host_of("h:5900"), "h");
        assert_eq!(host_of("[::1]:5900"), "::1");
    }

    #[tokio::test]
    async fn pinned_accepts_right_and_rejects_wrong() {
        let id = ServerIdentity::self_signed(&["localhost".into()]).unwrap();
        let ok = ClientTls {
            trust: Trust::Pinned(id.fingerprint()),
        };
        assert_eq!(pair(&id, &ok, "h:1").await.unwrap(), b"ola");
        let other = ServerIdentity::self_signed(&["localhost".into()]).unwrap();
        let bad = ClientTls {
            trust: Trust::Pinned(other.fingerprint()),
        };
        let e = pair(&id, &bad, "h:1").await.unwrap_err().to_string();
        assert!(e.contains("CERTIFICADO MUDOU"), "{e}");
    }

    #[tokio::test]
    async fn webpki_rejects_self_signed() {
        let id = ServerIdentity::self_signed(&["localhost".into()]).unwrap();
        assert!(pair(&id, &ClientTls::default(), "h:1").await.is_err());
        // adicionado explicitamente como ancora, passa (escolha do usuario)
        let tls = ClientTls {
            trust: Trust::WebPki {
                extra_roots: id.certs.clone(),
            },
        };
        assert_eq!(pair(&id, &tls, "h:1").await.unwrap(), b"ola");
        // mas o nome continua sendo conferido
        let other = ServerIdentity::self_signed(&["outro.example".into()]).unwrap();
        let tls = ClientTls {
            trust: Trust::WebPki {
                extra_roots: other.certs.clone(),
            },
        };
        assert!(pair(&other, &tls, "h:1").await.is_err());
    }

    #[tokio::test]
    async fn tofu_flow() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownHosts::new(dir.path().join("kh"));
        let id = ServerIdentity::self_signed(&["localhost".into()]).unwrap();
        // desconhecido sem accept_new: recusa
        let strict = ClientTls {
            trust: Trust::Tofu {
                store: store.clone(),
                accept_new: false,
            },
        };
        let e = pair(&id, &strict, "h:5900").await.unwrap_err().to_string();
        assert!(e.contains("desconhecido"), "{e}");
        assert!(store.get("h:5900").unwrap().is_none());
        // aceita e grava
        let accept = ClientTls {
            trust: Trust::Tofu {
                store: store.clone(),
                accept_new: true,
            },
        };
        pair(&id, &accept, "h:5900").await.unwrap();
        assert_eq!(store.get("h:5900").unwrap(), Some(id.fingerprint()));
        // depois disso o modo estrito aceita
        pair(&id, &strict, "h:5900").await.unwrap();
        // servidor troca de chave: erro mesmo com accept_new, e nada muda
        let id2 = ServerIdentity::self_signed(&["localhost".into()]).unwrap();
        let e = pair(&id2, &accept, "h:5900").await.unwrap_err().to_string();
        assert!(e.contains("CERTIFICADO MUDOU"), "{e}");
        assert_eq!(store.get("h:5900").unwrap(), Some(id.fingerprint()));
        assert!(store.add("h:5900", &id2.fingerprint()).is_err());
    }

    #[test]
    fn load_or_create_persists() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        let a = ServerIdentity::load_or_create(&c, &k, &["localhost".into()]).unwrap();
        let b = ServerIdentity::load_or_create(&c, &k, &["localhost".into()]).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }
}
