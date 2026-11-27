//! Configuracao do servidor central (TOML).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Arquivo de configuracao.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Endereco HTTPS (ex.: `0.0.0.0:8443`).
    pub listen: String,
    /// Diretorio de estado: CA, chaves, banco (`store.json`).
    pub state_dir: PathBuf,
    /// URL publica (emissor OIDC), ex.: `https://central.empresa:8443`.
    pub issuer: String,
    /// Nomes e IPs do certificado HTTPS. Vazio: host do `issuer`.
    pub tls_names: Vec<String>,
    /// `aud` dos tickets (o `oidc_client_id` dos servidores).
    pub client_id: String,
    /// Validade do ticket, em segundos.
    pub ticket_ttl: u64,
    /// Validade da sessao de login, em segundos.
    pub session_ttl: u64,
    /// Log de auditoria central (JSON lines). Vazio: `state_dir/audit.log`.
    pub audit_log: Option<PathBuf>,
    /// Falhas de login livres antes do bloqueio progressivo.
    pub lockout_free: u32,
    /// Conexoes HTTP simultaneas.
    pub max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "0.0.0.0:8443".into(),
            state_dir: PathBuf::from("central-state"),
            issuer: "https://127.0.0.1:8443".into(),
            tls_names: vec![],
            client_id: "openvnc".into(),
            ticket_ttl: 120,
            session_ttl: 900,
            audit_log: None,
            lockout_free: 5,
            max_connections: 256,
        }
    }
}

impl Config {
    /// Le e valida. Caminhos relativos sao relativos ao arquivo.
    pub fn load(path: &Path) -> Result<Self> {
        let txt =
            std::fs::read_to_string(path).with_context(|| format!("lendo {}", path.display()))?;
        let mut c: Config = toml::from_str(&txt).context("configuracao invalida")?;
        let base = path.parent().unwrap_or(Path::new("."));
        if c.state_dir.is_relative() {
            c.state_dir = base.join(&c.state_dir);
        }
        if let Some(a) = &c.audit_log {
            if a.is_relative() {
                c.audit_log = Some(base.join(a));
            }
        }
        c.validate()?;
        Ok(c)
    }

    /// Regras basicas.
    pub fn validate(&mut self) -> Result<()> {
        self.issuer = self.issuer.trim().trim_end_matches('/').to_owned();
        if !self.issuer.starts_with("https://") {
            bail!("issuer precisa ser https://");
        }
        if !(10..=3600).contains(&self.ticket_ttl) {
            bail!("ticket_ttl fora de 10..3600 segundos");
        }
        if !(60..=86400).contains(&self.session_ttl) {
            bail!("session_ttl fora de 60..86400 segundos");
        }
        if self.client_id.is_empty() {
            bail!("client_id vazio");
        }
        if self.max_connections == 0 {
            bail!("max_connections precisa ser > 0");
        }
        if self.tls_names.is_empty() {
            self.tls_names.push(issuer_host(&self.issuer));
        }
        Ok(())
    }

    /// Caminho do log de auditoria.
    pub fn audit_path(&self) -> PathBuf {
        self.audit_log
            .clone()
            .unwrap_or_else(|| self.state_dir.join("audit.log"))
    }

    /// Caminho do banco.
    pub fn store_path(&self) -> PathBuf {
        self.state_dir.join("store.json")
    }
}

/// Host do URL (sem porta nem colchetes).
pub fn issuer_host(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hostport = rest.split('/').next().unwrap_or(rest);
    if let Some(v6) = hostport.strip_prefix('[') {
        return v6.split(']').next().unwrap_or(v6).to_owned();
    }
    hostport.split(':').next().unwrap_or(hostport).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valida_e_deriva_nomes() {
        let mut c = Config {
            issuer: "https://central.empresa:8443/".into(),
            ..Config::default()
        };
        c.validate().unwrap();
        assert_eq!(c.issuer, "https://central.empresa:8443");
        assert_eq!(c.tls_names, vec!["central.empresa"]);
        assert_eq!(issuer_host("https://[::1]:8443"), "::1");
        let mut c = Config {
            issuer: "http://x".into(),
            ..Config::default()
        };
        assert!(c.validate().is_err());
    }
}
