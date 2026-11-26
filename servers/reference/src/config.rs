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
}

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

    /// Valida combinacoes perigosas. Normaliza `require_tls -> tls`.
    pub fn validate(&mut self, password: &Option<String>) -> anyhow::Result<()> {
        self.tls |= self.require_tls;
        if self.pairing && !self.tls {
            anyhow::bail!("pairing exige tls (o token so trafega dentro do TLS)");
        }
        let has_auth = password.is_some() || self.pairing;
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
