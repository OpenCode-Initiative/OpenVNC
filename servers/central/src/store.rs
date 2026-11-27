//! Banco do servidor central: um arquivo JSON gravado de forma atomica
//! (arquivo temporario + rename). A CLI de administracao grava; o servidor
//! le de novo quando o arquivo muda.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Permissoes conhecidas.
pub const PERMS: [&str; 4] = ["view", "control", "files", "clipboard"];

/// Usuario.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct User {
    /// Hash Argon2id (PHC).
    pub hash: String,
    /// Grupos.
    #[serde(default)]
    pub groups: BTreeSet<String>,
    /// Desativado (nao autentica).
    #[serde(default)]
    pub disabled: bool,
    /// Administrador (le a auditoria central).
    #[serde(default)]
    pub admin: bool,
}

/// Maquina cadastrada.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    /// Nome para exibir.
    pub name: String,
    /// Host ou IP.
    pub address: String,
    /// Porta do protocolo nativo.
    pub port: u16,
    /// Impressao digital do certificado do servidor.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// SHA-256 (hex) do segredo da maquina.
    pub secret_sha256: String,
}

/// Concessao de acesso.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    /// `user:<nome>` ou `group:<nome>`.
    pub subject: String,
    /// Id da maquina.
    pub machine: String,
    /// Permissoes.
    pub perms: BTreeSet<String>,
    /// Sobrepoe `ask_before_accept` do servidor.
    #[serde(default)]
    pub ask: Option<bool>,
}

/// Permissoes efetivas de um usuario numa maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// Uniao das permissoes (sempre inclui `view`).
    pub perms: Vec<String>,
    /// `Some(true)` se alguma concessao exige aprovacao.
    pub ask: Option<bool>,
}

/// Banco completo.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Store {
    /// Usuarios por nome.
    #[serde(default)]
    pub users: BTreeMap<String, User>,
    /// Grupos existentes.
    #[serde(default)]
    pub groups: BTreeSet<String>,
    /// Maquinas por id.
    #[serde(default)]
    pub machines: BTreeMap<String, Machine>,
    /// Concessoes.
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// Grava `data` em `p` de forma atomica. `private`: 0600 no Unix.
pub fn write_atomic(p: &Path, data: &[u8], private: bool) -> Result<()> {
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(d) = dir {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut f = o.open(&tmp).with_context(|| format!("gravando {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, p).with_context(|| format!("substituindo {}", p.display()))?;
    Ok(())
}

/// SHA-256 em hex.
pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Nome aceito para usuario, grupo ou maquina.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
}

/// Interpreta `view,control,...`.
pub fn parse_perms(s: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if !PERMS.contains(&p) {
            bail!("permissao desconhecida: {p} (use {})", PERMS.join(","));
        }
        out.insert(p.to_owned());
    }
    if out.is_empty() {
        bail!("nenhuma permissao informada");
    }
    Ok(out)
}

impl Store {
    /// Le `p` (inexistente: banco vazio).
    pub fn load(p: &Path) -> Result<Self> {
        match std::fs::read(p) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("banco invalido: {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Grava de forma atomica.
    pub fn save(&self, p: &Path) -> Result<()> {
        let mut b = serde_json::to_vec_pretty(self)?;
        b.push(b'\n');
        write_atomic(p, &b, true)
    }

    /// Permissoes efetivas: uniao das concessoes do usuario e dos grupos
    /// dele. `None`: sem acesso (ou usuario/maquina inexistente/desativado).
    pub fn effective(&self, user: &str, machine: &str) -> Option<Effective> {
        let u = self.users.get(user).filter(|u| !u.disabled)?;
        self.machines.get(machine)?;
        let mut perms: BTreeSet<String> = BTreeSet::new();
        let mut ask = None;
        let mut any = false;
        for g in self.grants.iter().filter(|g| g.machine == machine) {
            let hit = match g.subject.split_once(':') {
                Some(("user", n)) => n == user,
                Some(("group", n)) => u.groups.contains(n) && self.groups.contains(n),
                _ => false,
            };
            if !hit {
                continue;
            }
            any = true;
            perms.extend(g.perms.iter().cloned());
            ask = match (ask, g.ask) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (a, None) => a,
                (_, b) => b,
            };
        }
        if !any {
            return None;
        }
        // qualquer permissao implica ver a tela
        perms.insert("view".into());
        Some(Effective {
            perms: PERMS
                .iter()
                .filter(|p| perms.contains(**p))
                .map(|p| (*p).to_owned())
                .collect(),
            ask,
        })
    }

    /// Grupos validos do usuario.
    pub fn groups_of(&self, user: &str) -> Vec<String> {
        self.users
            .get(user)
            .map(|u| {
                u.groups
                    .iter()
                    .filter(|g| self.groups.contains(*g))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Confere o segredo de uma maquina (comparacao do hash em tempo fixo).
    pub fn machine_secret_ok(&self, id: &str, secret: &str) -> bool {
        let Some(m) = self.machines.get(id) else {
            return false;
        };
        let got = sha256_hex(secret.as_bytes());
        let want = m.secret_sha256.as_bytes();
        got.len() == want.len()
            && got
                .bytes()
                .zip(want)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    /// Adiciona ou substitui a concessao de `subject` em `machine`.
    pub fn grant(&mut self, subject: &str, machine: &str, perms: BTreeSet<String>, ask: Option<bool>) -> Result<()> {
        match subject.split_once(':') {
            Some(("user", n)) if self.users.contains_key(n) => {}
            Some(("group", n)) if self.groups.contains(n) => {}
            _ => bail!("sujeito inexistente: {subject}"),
        }
        if !self.machines.contains_key(machine) {
            bail!("maquina inexistente: {machine}");
        }
        self.grants
            .retain(|g| !(g.subject == subject && g.machine == machine));
        self.grants.push(Grant {
            subject: subject.to_owned(),
            machine: machine.to_owned(),
            perms,
            ask,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Store {
        let mut s = Store::default();
        s.groups.insert("suporte".into());
        s.users.insert(
            "alice".into(),
            User {
                hash: openvnc_security::passhash::hash("senha-da-alice").unwrap(),
                groups: ["suporte".to_string()].into(),
                ..User::default()
            },
        );
        s.users.insert("bob".into(), User::default());
        s.machines.insert(
            "pc-01".into(),
            Machine {
                name: "PC 01".into(),
                address: "10.0.0.1".into(),
                port: 5902,
                fingerprint: None,
                secret_sha256: sha256_hex(b"segredo-maquina"),
            },
        );
        s
    }

    #[test]
    fn uniao_de_permissoes_e_grupos() {
        let mut s = base();
        assert_eq!(s.effective("alice", "pc-01"), None);
        s.grant("group:suporte", "pc-01", parse_perms("control").unwrap(), None)
            .unwrap();
        s.grant("user:alice", "pc-01", parse_perms("files").unwrap(), Some(true))
            .unwrap();
        let e = s.effective("alice", "pc-01").unwrap();
        assert_eq!(e.perms, vec!["view", "control", "files"]);
        assert_eq!(e.ask, Some(true));
        assert_eq!(s.effective("bob", "pc-01"), None);
        // regravar a concessao substitui
        s.grant("user:alice", "pc-01", parse_perms("view").unwrap(), None)
            .unwrap();
        assert_eq!(s.effective("alice", "pc-01").unwrap().ask, None);
        // usuario desativado perde tudo
        s.users.get_mut("alice").unwrap().disabled = true;
        assert_eq!(s.effective("alice", "pc-01"), None);
        assert!(s.grant("user:zeca", "pc-01", parse_perms("view").unwrap(), None).is_err());
        assert!(parse_perms("view,root").is_err());
        assert!(parse_perms("").is_err());
    }

    #[test]
    fn grava_atomico_e_le_de_volta() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("store.json");
        assert!(Store::load(&p).unwrap().users.is_empty());
        let s = base();
        s.save(&p).unwrap();
        let t = Store::load(&p).unwrap();
        assert!(openvnc_security::passhash::verify(
            b"senha-da-alice",
            &t.users["alice"].hash
        ));
        assert!(!openvnc_security::passhash::verify(b"errada", &t.users["alice"].hash));
        assert!(t.machine_secret_ok("pc-01", "segredo-maquina"));
        assert!(!t.machine_secret_ok("pc-01", "outro"));
        assert!(!t.machine_secret_ok("pc-02", "segredo-maquina"));
        // texto do banco nao contem a senha nem o segredo
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("senha-da-alice") && !raw.contains("segredo-maquina"));
        assert!(valid_name("pc-01") && !valid_name("a b") && !valid_name(""));
    }
}
