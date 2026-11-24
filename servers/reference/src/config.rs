//! Configuracao TOML com padroes seguros.

use serde::Deserialize;
use std::net::SocketAddr;

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

    /// Valida combinacoes perigosas.
    pub fn validate(&self, password: &Option<String>) -> anyhow::Result<()> {
        if password.is_none() && !self.allow_no_auth {
            anyhow::bail!(
                "sem senha: defina OPENVNC_PASSWORD (ou `password`) ou use allow_no_auth = true"
            );
        }
        if password.is_none() && !self.listen.ip().is_loopback() {
            anyhow::bail!("recuso escutar fora do loopback sem senha");
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
        let c = Config::default();
        assert!(c.listen.ip().is_loopback());
        assert!(!c.allow_no_auth);
        assert!(c.view_only);
        assert_eq!(c.capture, CaptureKind::TestPattern);
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
        assert!(c.validate(&Some("x".into())).is_ok());
    }
}
