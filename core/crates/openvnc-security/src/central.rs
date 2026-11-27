//! Cliente do servidor central OpenVNC (empresa, on-premises).
//!
//! Fluxo: [`Central::login`] com usuario e senha devolve uma sessao curta;
//! [`Central::machines`] lista as maquinas liberadas para o usuario e
//! [`Central::ticket`] pede um ticket (JWT ES256 de vida curta) para uma
//! delas. O ticket vai como segredo OIDC no protocolo nativo e o servidor
//! da maquina o confere com [`crate::oidc::Verifier`].
//!
//! As chamadas HTTP sao bloqueantes; use em `spawn_blocking`.

use serde_json::Value;
use zeroize::Zeroizing;

use crate::oidc::{http_agent, Error};

/// Maquina do catalogo, com as permissoes do usuario nela.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    /// Id estavel (vai no ticket).
    pub id: String,
    /// Nome para exibir.
    pub name: String,
    /// Host ou IP.
    pub address: String,
    /// Porta do protocolo nativo.
    pub port: u16,
    /// Impressao digital SHA-256 do certificado do servidor (pode faltar).
    pub fingerprint: Option<String>,
    /// Permissoes (`view`, `control`, `files`, `clipboard`).
    pub perms: Vec<String>,
}

/// Sessao aberta no servidor central (o token nunca aparece no `Debug`).
pub struct Session {
    token: Zeroizing<String>,
    /// Usuario autenticado.
    pub user: String,
    /// Validade, em segundos.
    pub expires_in: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session({}, ***)", self.user)
    }
}

/// Cliente do servidor central.
pub struct Central {
    base: String,
    agent: ureq::Agent,
}

fn api_err(what: &str, e: ureq::Error) -> Error {
    match e {
        ureq::Error::Status(code, resp) => {
            let msg = resp
                .into_json::<Value>()
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| format!("HTTP {code}"));
            Error(format!("{what}: {msg}"))
        }
        e => Error(format!("{what}: {e}")),
    }
}

impl Central {
    /// `url` precisa ser `https://` (o central so fala HTTPS). `ca_pem` e a
    /// CA do central, se nao estiver instalada no sistema.
    pub fn new(url: &str, ca_pem: Option<&[u8]>) -> Result<Self, Error> {
        let base = url.trim().trim_end_matches('/').to_owned();
        if !base.starts_with("https://") {
            return Err(Error(format!(
                "URL do servidor central precisa ser https: {base}"
            )));
        }
        Ok(Self {
            base,
            agent: http_agent(ca_pem)?,
        })
    }

    /// URL base.
    pub fn url(&self) -> &str {
        &self.base
    }

    /// Autentica com usuario e senha.
    pub fn login(&self, user: &str, password: &str) -> Result<Session, Error> {
        let v: Value = self
            .agent
            .post(&format!("{}/api/login", self.base))
            .send_json(serde_json::json!({"user": user, "password": password}))
            .map_err(|e| api_err("login", e))?
            .into_json()
            .map_err(|e| Error(format!("login: {e}")))?;
        let token = v
            .get("session")
            .and_then(Value::as_str)
            .ok_or_else(|| Error("login: resposta sem sessao".into()))?;
        Ok(Session {
            token: Zeroizing::new(token.to_owned()),
            user: v
                .get("user")
                .and_then(Value::as_str)
                .unwrap_or(user)
                .to_owned(),
            expires_in: v.get("expires_in").and_then(Value::as_u64).unwrap_or(0),
        })
    }

    fn bearer(s: &Session) -> String {
        format!("Bearer {}", s.token.as_str())
    }

    /// Maquinas liberadas para o usuario da sessao.
    pub fn machines(&self, s: &Session) -> Result<Vec<Machine>, Error> {
        let v: Value = self
            .agent
            .get(&format!("{}/api/machines", self.base))
            .set("Authorization", &Self::bearer(s))
            .call()
            .map_err(|e| api_err("catalogo", e))?
            .into_json()
            .map_err(|e| Error(format!("catalogo: {e}")))?;
        Ok(parse_machines(&v))
    }

    /// Ticket (JWT) para conectar em `machine`.
    pub fn ticket(&self, s: &Session, machine: &str) -> Result<String, Error> {
        let v: Value = self
            .agent
            .post(&format!("{}/api/ticket", self.base))
            .set("Authorization", &Self::bearer(s))
            .send_json(serde_json::json!({"machine": machine}))
            .map_err(|e| api_err("ticket", e))?
            .into_json()
            .map_err(|e| Error(format!("ticket: {e}")))?;
        v.get("ticket")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error("ticket: resposta sem ticket".into()))
    }

    /// Envia linhas de auditoria (JSON por linha) autenticado pelo segredo
    /// da maquina.
    pub fn send_audit(&self, machine: &str, secret: &str, lines: &str) -> Result<(), Error> {
        self.agent
            .post(&format!("{}/api/audit", self.base))
            .set("Authorization", &format!("Machine {machine} {secret}"))
            .set("Content-Type", "application/x-ndjson")
            .send_string(lines)
            .map_err(|e| api_err("auditoria", e))?;
        Ok(())
    }
}

/// Interpreta a resposta de `/api/machines`.
pub fn parse_machines(v: &Value) -> Vec<Machine> {
    v.get("machines")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let s = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_owned);
                    Some(Machine {
                        id: s("id")?,
                        name: s("name").unwrap_or_default(),
                        address: s("address")?,
                        port: u16::try_from(m.get("port")?.as_u64()?).ok()?,
                        fingerprint: s("fingerprint").filter(|f| !f.is_empty()),
                        perms: m
                            .get("perms")
                            .and_then(Value::as_array)
                            .map(|p| {
                                p.iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exige_https_e_interpreta_catalogo() {
        assert!(Central::new("http://central.test", None).is_err());
        let v = serde_json::json!({"machines": [
            {"id": "pc-01", "name": "Financeiro", "address": "10.0.0.5", "port": 5901,
             "fingerprint": "AA:BB", "perms": ["view", "control"]},
            {"id": "sem-endereco"},
            {"id": "porta-ruim", "address": "x", "port": 70000},
        ]});
        let m = parse_machines(&v);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].port, 5901);
        assert_eq!(m[0].perms, vec!["view", "control"]);
    }
}
