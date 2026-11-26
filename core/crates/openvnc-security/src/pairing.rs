//! Pareamento de dispositivos.
//!
//! Cada dispositivo recebe um id e um token aleatorio de 256 bits, mostrado
//! **uma unica vez** no pareamento. O servidor guarda so o SHA-256 do token.
//! O cliente autentica via VeNCrypt X509Plain (usuario = id, senha = token),
//! portanto sempre dentro de TLS. Revogar marca o dispositivo; ele nunca
//! mais autentica, e o id nao e reaproveitado.
//!
//! Formato do arquivo (uma linha por dispositivo, campos separados por TAB):
//! `id  sha256-hex  criado-unix  active|revoked  nome`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use openvnc_core::{Error, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Um dispositivo pareado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Identificador (usuario no X509Plain).
    pub id: String,
    /// Nome livre.
    pub name: String,
    /// Segundos desde a epoca UNIX.
    pub created: u64,
    /// Revogado?
    pub revoked: bool,
    hash: String,
}

/// Armazenamento de dispositivos em arquivo texto.
#[derive(Debug, Clone)]
pub struct DeviceStore {
    path: PathBuf,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash_token(token: &[u8]) -> String {
    hex(&Sha256::digest(token))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn valid_name(s: &str) -> bool {
    !s.chars().any(|c| c == '\t' || c == '\n' || c == '\r')
}

impl DeviceStore {
    /// Usa (ou criara) o arquivo `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        DeviceStore { path: path.into() }
    }

    /// Caminho do arquivo.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lista todos os dispositivos (inclusive revogados).
    pub fn list(&self) -> Result<Vec<Device>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut v = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.splitn(5, '\t').collect();
            let bad =
                || Error::Protocol(format!("{}:{}: linha invalida", self.path.display(), n + 1));
            if f.len() != 5 || f[1].len() != 64 {
                return Err(bad());
            }
            v.push(Device {
                id: f[0].into(),
                hash: f[1].into(),
                created: f[2].parse().map_err(|_| bad())?,
                revoked: match f[3] {
                    "active" => false,
                    "revoked" => true,
                    _ => return Err(bad()),
                },
                name: f[4].into(),
            });
        }
        Ok(v)
    }

    fn save(&self, devs: &[Device]) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)?;
            }
        }
        let mut s = String::from("# dispositivos pareados do OpenVNC (nao editar a mao)\n");
        for d in devs {
            s.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                d.id,
                d.hash,
                d.created,
                if d.revoked { "revoked" } else { "active" },
                d.name
            ));
        }
        // grava em arquivo temporario e renomeia (atomico)
        let tmp = self.path.with_extension("tmp");
        {
            let mut o = fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            f.write_all(s.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Pareia um novo dispositivo. Retorna o dispositivo e o token (que nao
    /// fica guardado em lugar nenhum: entregue-o ao cliente agora).
    pub fn pair(&self, name: &str) -> Result<(Device, Zeroizing<String>)> {
        if !valid_name(name) {
            return Err(Error::Protocol("nome com caractere de controle".into()));
        }
        let mut devs = self.list()?;
        let mut rng = rand::rngs::OsRng;
        let id = loop {
            let mut b = [0u8; 6];
            rng.fill_bytes(&mut b);
            let id = format!("dev-{}", hex(&b));
            if !devs.iter().any(|d| d.id == id) {
                break id;
            }
        };
        let mut t = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *t);
        let token = Zeroizing::new(hex(&*t));
        let d = Device {
            id,
            name: name.into(),
            created: now(),
            revoked: false,
            hash: hash_token(token.as_bytes()),
        };
        devs.push(d.clone());
        self.save(&devs)?;
        Ok((d, token))
    }

    /// Revoga `id`. Erro se nao existir; revogar de novo nao e erro.
    pub fn revoke(&self, id: &str) -> Result<()> {
        let mut devs = self.list()?;
        let d = devs
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or_else(|| Error::Protocol(format!("dispositivo {id} nao existe")))?;
        d.revoked = true;
        self.save(&devs)
    }

    /// Confere credenciais. Le o arquivo a cada chamada, entao uma
    /// revogacao vale para a proxima conexao sem reiniciar o servidor.
    pub fn verify(&self, id: &str, token: &[u8]) -> Verdict {
        let devs = match self.list() {
            Ok(d) => d,
            Err(_) => return Verdict::StoreError,
        };
        let Some(d) = devs.iter().find(|d| d.id == id) else {
            return Verdict::Unknown;
        };
        let h = hash_token(token);
        let eq = h
            .bytes()
            .zip(d.hash.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0;
        if !eq {
            Verdict::BadToken
        } else if d.revoked {
            Verdict::Revoked
        } else {
            Verdict::Ok
        }
    }
}

/// Resultado de [`DeviceStore::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Aceito.
    Ok,
    /// Id desconhecido.
    Unknown,
    /// Token errado.
    BadToken,
    /// Dispositivo revogado.
    Revoked,
    /// Arquivo ilegivel (falha fechada).
    StoreError,
}

impl Verdict {
    /// Texto curto para o log de auditoria.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Unknown => "unknown_device",
            Verdict::BadToken => "bad_token",
            Verdict::Revoked => "revoked",
            Verdict::StoreError => "store_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_verify_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let st = DeviceStore::new(dir.path().join("sub/devices"));
        assert!(st.list().unwrap().is_empty());
        let (d, tok) = st.pair("notebook").unwrap();
        let (d2, tok2) = st.pair("celular").unwrap();
        assert_ne!(d.id, d2.id);
        assert_eq!(tok.len(), 64);
        assert_eq!(st.verify(&d.id, tok.as_bytes()), Verdict::Ok);
        assert_eq!(st.verify(&d.id, tok2.as_bytes()), Verdict::BadToken);
        assert_eq!(st.verify("dev-x", tok.as_bytes()), Verdict::Unknown);
        // o token nao esta no arquivo
        let raw = fs::read_to_string(st.path()).unwrap();
        assert!(!raw.contains(tok.as_str()));
        st.revoke(&d.id).unwrap();
        assert_eq!(st.verify(&d.id, tok.as_bytes()), Verdict::Revoked);
        assert_eq!(st.verify(&d2.id, tok2.as_bytes()), Verdict::Ok);
        assert!(st.revoke("dev-nao").is_err());
        assert!(st.pair("a\tb").is_err());
        let l = st.list().unwrap();
        assert_eq!(l.len(), 2);
        assert!(l[0].revoked && !l[1].revoked);
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("d");
        fs::write(&p, "lixo\n").unwrap();
        let st = DeviceStore::new(&p);
        assert!(st.list().is_err());
        assert_eq!(st.verify("lixo", b""), Verdict::StoreError);
    }
}
