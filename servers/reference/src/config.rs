//! Configuracao TOML com padroes seguros.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Fonte de quadros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureKind {
    /// Tela sintetica animada (padrao: nao expoe a tela real).
    TestPattern,
    /// Captura nativa do SO.
    Native,
}

/// Arquivo de configuracao. Todos os campos sao opcionais.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Endereco de escuta. Padrao: so loopback.
    pub listen: SocketAddr,
    /// Senha VNC Auth (prefira `password_env`).
    pub password: Option<String>,
    /// Variavel de ambiente com a senha.
    pub password_env: Option<String>,
    /// Aceitar clientes sem senha (inseguro).
    pub allow_no_auth: bool,
    /// Ignorar teclado/mouse dos clientes.
    pub view_only: bool,
    /// Fonte de quadros.
    pub capture: CaptureKind,
    /// Tamanho da tela sintetica.
    pub test_pattern_size: (u16, u16),
    /// Limite de quadros por segundo.
    pub max_fps: u32,
    /// Limite de clientes simultaneos.
    pub max_clients: usize,
    /// Nome do desktop.
    pub name: String,
    /// Oferecer VeNCrypt (TLS 1.3).
    pub tls: bool,
    /// Oferecer **somente** VeNCrypt (sem tipos em claro). Implica `tls`.
    pub require_tls: bool,
    /// Certificado PEM. Padrao: `<state_dir>/server.crt` (gerado
    /// autoassinado na primeira execucao).
    pub tls_cert: Option<PathBuf>,
    /// Chave PEM. Padrao: `<state_dir>/server.key`.
    pub tls_key: Option<PathBuf>,
    /// Nomes (SAN) do certificado autoassinado gerado.
    pub tls_names: Vec<String>,
    /// Arquivo de dispositivos pareados. Padrao: `<state_dir>/devices`.
    /// Com `pairing = true`, habilita VeNCrypt X509Plain.
    pub devices: Option<PathBuf>,
    /// Autenticar dispositivos pareados.
    pub pairing: bool,
    /// Log de auditoria (JSON lines). Padrao: `<state_dir>/audit.log`
    /// quando `tls` ou `pairing` estao ligados.
    pub audit_log: Option<PathBuf>,
    /// Endereco do protocolo nativo (QUIC + TCP/TLS na mesma porta).
    /// Desligado por padrao.
    pub native_listen: Option<SocketAddr>,
    /// Diretorio de estado. Padrao: `OPENVNC_SERVER_DIR`, senao
    /// `%APPDATA%/openvnc-server` ou `~/.local/share/openvnc-server`.
    pub state_dir: Option<PathBuf>,
    /// Hash Argon2id (PHC) da senha de acesso remoto. Conferido no
    /// X509Plain (usuario [`REMOTE_USER`], dentro do TLS).
    pub password_hash: Option<String>,
    /// Senha cifrada com DPAPI da maquina (hex), so para clientes VNC
    /// antigos (VNC Auth). Ausente = sem compatibilidade.
    pub password_protected: Option<String>,
    /// Hash Argon2id da senha de administracao local (Configuracoes e
    /// "Parar o servidor").
    pub admin_password_hash: Option<String>,
    /// O assistente de configuracao ja foi concluido.
    pub setup_done: bool,
    /// Aceitar so enderecos de rede local (privados, loopback, link-local).
    pub lan_only: bool,
    /// Perguntar ao usuario local antes de aceitar cada conexao.
    pub ask_before_accept: bool,
    /// Permitir conexao sem senha, desde que o usuario local autorize na
    /// hora (como o AnyDesk). Quem entra com senha ou dispositivo pareado
    /// nao passa pela pergunta.
    pub allow_attended: bool,
    /// Permitir enviar arquivos deste computador ao cliente.
    pub files_send: bool,
    /// Permitir receber arquivos do cliente.
    pub files_receive: bool,
    /// Pasta de recebimento. Padrao: `Downloads\OpenVNC` do usuario.
    pub files_dir: Option<PathBuf>,
    /// Tamanho maximo de cada arquivo recebido, em MiB.
    pub files_max_mb: u64,
}

/// Usuario do X509Plain que autentica com a senha de acesso remoto.
pub const REMOTE_USER: &str = "openvnc";

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:5900".parse().expect("endereco fixo"),
            password: None,
            password_env: Some("OPENVNC_PASSWORD".into()),
            allow_no_auth: false,
            view_only: true,
            capture: CaptureKind::TestPattern,
            test_pattern_size: (800, 600),
            max_fps: 30,
            max_clients: 8,
            name: "OpenVNC".into(),
            tls: false,
            require_tls: false,
            tls_cert: None,
            tls_key: None,
            tls_names: vec!["localhost".into()],
            devices: None,
            pairing: false,
            audit_log: None,
            native_listen: None,
            state_dir: None,
            password_hash: None,
            password_protected: None,
            admin_password_hash: None,
            setup_done: false,
            lan_only: false,
            ask_before_accept: false,
            allow_attended: false,
            files_send: false,
            files_receive: false,
            files_dir: None,
            files_max_mb: 1024,
        }
    }
}

impl Config {
    /// Le de um arquivo TOML.
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(s)?)
    }

    /// Senha efetiva (arquivo tem precedencia sobre o ambiente).
    pub fn resolve_password(&self) -> Option<String> {
        self.password.clone().or_else(|| {
            self.password_env
                .as_deref()
                .and_then(|v| std::env::var(v).ok())
                .filter(|p| !p.is_empty())
        })
    }

    /// Diretorio de estado efetivo.
    pub fn state_dir(&self) -> PathBuf {
        if let Some(d) = &self.state_dir {
            return d.clone();
        }
        if let Some(d) = std::env::var_os("OPENVNC_SERVER_DIR") {
            return d.into();
        }
        if let Some(d) = std::env::var_os("APPDATA") {
            return PathBuf::from(d).join("openvnc-server");
        }
        if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(d).join("openvnc-server");
        }
        match std::env::var_os("HOME") {
            Some(h) => PathBuf::from(h).join(".local/share/openvnc-server"),
            None => PathBuf::from("openvnc-server"),
        }
    }

    /// Arquivo de dispositivos efetivo.
    pub fn devices_path(&self) -> PathBuf {
        self.devices
            .clone()
            .unwrap_or_else(|| self.state_dir().join("devices"))
    }

    /// Certificado e chave efetivos.
    pub fn tls_paths(&self) -> (PathBuf, PathBuf) {
        let d = self.state_dir();
        (
            self.tls_cert
                .clone()
                .unwrap_or_else(|| d.join("server.crt")),
            self.tls_key.clone().unwrap_or_else(|| d.join("server.key")),
        )
    }

    /// Log de auditoria efetivo (`None` = desligado).
    pub fn audit_path(&self) -> Option<PathBuf> {
        self.audit_log
            .clone()
            .or_else(|| (self.tls || self.pairing).then(|| self.state_dir().join("audit.log")))
    }

    /// Pasta de recebimento efetiva.
    pub fn files_dir(&self) -> PathBuf {
        if let Some(d) = &self.files_dir {
            return d.clone();
        }
        let home = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| self.state_dir());
        home.join("Downloads").join("OpenVNC")
    }

    /// `ip` e aceito com `lan_only`?
    pub fn peer_allowed(&self, ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        if !self.lan_only {
            return true;
        }
        match ip {
            IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
            IpAddr::V6(v) => match v.to_ipv4_mapped() {
                Some(m) => m.is_private() || m.is_loopback() || m.is_link_local(),
                None => {
                    v.is_loopback()
                        || (v.segments()[0] & 0xfe00) == 0xfc00
                        || (v.segments()[0] & 0xffc0) == 0xfe80
                }
            },
        }
    }

    /// Valida combinacoes perigosas. Normaliza `require_tls -> tls`.
    pub fn validate(&mut self, password: &Option<String>) -> anyhow::Result<()> {
        self.tls |= self.require_tls;
        if self.pairing && !self.tls {
            anyhow::bail!("pairing exige tls (o token so trafega dentro do TLS)");
        }
        if self.password_hash.is_some() && !self.tls {
            anyhow::bail!("password_hash exige tls (a senha so trafega dentro do TLS)");
        }
        let has_auth = password.is_some()
            || self.pairing
            || self.password_hash.is_some()
            || self.allow_attended;
        if !has_auth && !self.allow_no_auth {
            anyhow::bail!(
                "sem senha: defina OPENVNC_PASSWORD (ou `password`), use pairing = true ou allow_no_auth = true"
            );
        }
        if self.allow_no_auth && !self.listen.ip().is_loopback() {
            anyhow::bail!("recuso escutar fora do loopback com allow_no_auth");
        }
        if self.allow_no_auth && self.native_listen.is_some_and(|a| !a.ip().is_loopback()) {
            anyhow::bail!("recuso o protocolo nativo fora do loopback com allow_no_auth");
        }
        if !self.listen.ip().is_loopback() && !self.require_tls {
            tracing::warn!(
                "escutando fora do loopback sem require_tls: senhas VNC Auth sao fracas e o trafego vai em claro"
            );
        }
        if password.as_ref().is_some_and(|p| p.len() > 8) {
            tracing::warn!("VNC Auth usa so os 8 primeiros caracteres da senha");
        }
        if !(1..=120).contains(&self.max_fps) {
            anyhow::bail!("max_fps deve estar entre 1 e 120");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let mut c = Config::default();
        assert!(c.listen.ip().is_loopback());
        assert!(!c.allow_no_auth);
        assert!(c.view_only);
        assert_eq!(c.capture, CaptureKind::TestPattern);
        assert!(c.validate(&None).is_err());
        assert!(!c.tls && !c.pairing);
    }

    #[test]
    fn tls_rules() {
        let mut c = Config {
            require_tls: true,
            pairing: true,
            listen: "0.0.0.0:5900".parse().unwrap(),
            ..Default::default()
        };
        // so pareamento, fora do loopback, TLS obrigatorio: ok
        assert!(c.validate(&None).is_ok());
        assert!(c.tls);
        let mut c = Config {
            pairing: true,
            ..Default::default()
        };
        assert!(c.validate(&None).is_err());
    }

    #[test]
    fn parse_and_reject_unknown() {
        let c = Config::from_toml("capture = \"native\"\nmax_fps = 15\nview_only = false").unwrap();
        assert_eq!(c.capture, CaptureKind::Native);
        assert_eq!(c.max_fps, 15);
        assert!(Config::from_toml("senha = \"x\"").is_err());
    }

    #[test]
    fn lan_only() {
        let c = Config {
            lan_only: true,
            ..Default::default()
        };
        assert!(c.peer_allowed("192.168.0.5".parse().unwrap()));
        assert!(c.peer_allowed("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!c.peer_allowed("8.8.8.8".parse().unwrap()));
        assert!(Config::default().peer_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn no_auth_only_on_loopback() {
        let mut c = Config {
            allow_no_auth: true,
            ..Default::default()
        };
        assert!(c.validate(&None).is_ok());
        c.listen = "0.0.0.0:5900".parse().unwrap();
        assert!(c.validate(&None).is_err());
        assert!(c.validate(&Some("x".into())).is_err());
        c.allow_no_auth = false;
        assert!(c.validate(&Some("x".into())).is_ok());
    }
}
