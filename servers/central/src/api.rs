//! Rotas HTTP do servidor central: descoberta OIDC, JWKS, login, catalogo,
//! tickets, fluxo de codigo de dispositivo e auditoria.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use openvnc_security::audit::AuditLog;
use openvnc_security::oidc::SCOPE_MACHINE;
use openvnc_security::passhash;

use crate::config::Config;
use crate::http::{html_escape, Request, Response};
use crate::store::{valid_name, Store};
use crate::token::{random_token, Signer, TicketReq};

/// Validade do codigo de dispositivo.
const DEVICE_TTL: Duration = Duration::from_secs(600);
/// Intervalo de consulta anunciado.
const DEVICE_INTERVAL: u64 = 2;
/// Maximo de codigos pendentes.
const MAX_DEVICES: usize = 1024;
/// Maximo de sessoes.
const MAX_SESSIONS: usize = 10_000;
/// Tamanho maximo de um evento remoto.
const MAX_EVENT: usize = 8 * 1024;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn key_of(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

/// Bloqueio progressivo por chave (usuario ou IP).
pub struct Lockout {
    free: u32,
    map: HashMap<String, (u32, Option<Instant>)>,
}

impl Lockout {
    /// `free` falhas sem bloqueio.
    pub fn new(free: u32) -> Self {
        Self {
            free,
            map: HashMap::new(),
        }
    }

    /// Segundos restantes de bloqueio.
    pub fn blocked(&self, k: &str) -> Option<u64> {
        let (_, until) = self.map.get(k)?;
        let left = until.as_ref()?.checked_duration_since(Instant::now())?;
        Some(left.as_secs().max(1))
    }

    /// Registra falha.
    pub fn fail(&mut self, k: &str) {
        if self.map.len() > 50_000 {
            let now = Instant::now();
            self.map.retain(|_, (_, u)| u.is_some_and(|u| u > now));
        }
        let e = self.map.entry(k.to_owned()).or_insert((0, None));
        e.0 += 1;
        if e.0 > self.free {
            let n = (e.0 - self.free - 1).min(10);
            let secs = (30u64 << n).min(900);
            e.1 = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    /// Sucesso zera.
    pub fn ok(&mut self, k: &str) {
        self.map.remove(k);
    }
}

struct Sess {
    user: String,
    exp: Instant,
}

struct Device {
    user_code: String,
    machine: String,
    client_id: String,
    exp: Instant,
    approved: Option<String>,
    denied: bool,
    last_poll: Option<Instant>,
}

struct Loaded {
    store: Store,
    mtime: Option<SystemTime>,
}

/// Estado compartilhado do servidor.
pub struct App {
    /// Configuracao.
    pub cfg: Config,
    store_path: PathBuf,
    loaded: Mutex<Loaded>,
    signer: Signer,
    /// CA em PEM.
    pub ca_pem: String,
    /// Auditoria central.
    pub audit: Arc<AuditLog>,
    sessions: Mutex<HashMap<[u8; 32], Sess>>,
    devices: Mutex<HashMap<[u8; 32], Device>>,
    lockout: Mutex<Lockout>,
    dummy_hash: String,
}

enum Auth {
    Ok(String),
    Fail(Response),
}

impl App {
    /// Monta o estado.
    pub fn new(
        cfg: Config,
        signing_pkcs8: &[u8],
        ca_pem: String,
        audit: Arc<AuditLog>,
    ) -> anyhow::Result<Self> {
        let store_path = cfg.store_path();
        let store = Store::load(&store_path)?;
        let mtime = std::fs::metadata(&store_path)
            .and_then(|m| m.modified())
            .ok();
        Ok(Self {
            lockout: Mutex::new(Lockout::new(cfg.lockout_free)),
            cfg,
            store_path,
            loaded: Mutex::new(Loaded { store, mtime }),
            signer: Signer::new(signing_pkcs8)?,
            ca_pem,
            audit,
            sessions: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            dummy_hash: passhash::hash(&random_token(16)).map_err(anyhow::Error::msg)?,
        })
    }

    /// Copia do banco, relida se o arquivo mudou.
    pub fn store(&self) -> Store {
        let mut g = self.loaded.lock().unwrap();
        let mt = std::fs::metadata(&self.store_path)
            .and_then(|m| m.modified())
            .ok();
        if mt != g.mtime {
            match Store::load(&self.store_path) {
                Ok(s) => {
                    g.store = s;
                    g.mtime = mt;
                    tracing::info!("banco recarregado");
                }
                Err(e) => tracing::warn!("banco invalido, mantendo o anterior: {e:#}"),
            }
        }
        g.store.clone()
    }

    fn rec(&self, event: &str, fields: &[(&str, &str)]) {
        self.audit.record(event, fields);
    }

    /// Confere usuario e senha com bloqueio progressivo (bloqueante: Argon2).
    fn check_password(
        &self,
        user: &str,
        password: &str,
        ip: IpAddr,
        via: &str,
    ) -> Result<(), Response> {
        let ip_s = ip.to_string();
        let ku = format!("u:{user}");
        let ki = format!("i:{ip_s}");
        {
            let l = self.lockout.lock().unwrap();
            if let Some(s) = l.blocked(&ku).or_else(|| l.blocked(&ki)) {
                self.rec(
                    "central_login",
                    &[
                        ("user", user),
                        ("ip", &ip_s),
                        ("via", via),
                        ("result", "bloqueado"),
                    ],
                );
                return Err(Response::error(
                    429,
                    &format!("muitas tentativas, aguarde {s} s"),
                ));
            }
        }
        let st = self.store();
        let u = st.users.get(user);
        // usuario inexistente tambem paga o Argon2 (nao revela existencia)
        let hash = u.map(|u| u.hash.as_str()).unwrap_or(&self.dummy_hash);
        let good = passhash::verify(password.as_bytes(), hash) && u.is_some_and(|u| !u.disabled);
        let mut l = self.lockout.lock().unwrap();
        if good {
            l.ok(&ku);
            l.ok(&ki);
            drop(l);
            self.rec(
                "central_login",
                &[
                    ("user", user),
                    ("ip", &ip_s),
                    ("via", via),
                    ("result", "ok"),
                ],
            );
            Ok(())
        } else {
            l.fail(&ku);
            l.fail(&ki);
            drop(l);
            self.rec(
                "central_login",
                &[
                    ("user", user),
                    ("ip", &ip_s),
                    ("via", via),
                    ("result", "falha"),
                ],
            );
            Err(Response::error(401, "usuario ou senha invalidos"))
        }
    }

    fn session_user(&self, r: &Request) -> Auth {
        let Some(tok) = r
            .header("authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
        else {
            return Auth::Fail(Response::error(401, "sessao ausente"));
        };
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, v| v.exp > now);
        let Some(sess) = s.get(&key_of(tok.trim())) else {
            return Auth::Fail(Response::error(401, "sessao invalida ou expirada"));
        };
        let user = sess.user.clone();
        drop(s);
        // usuario removido ou desativado perde a sessao na hora
        if self.store().users.get(&user).is_none_or(|u| u.disabled) {
            return Auth::Fail(Response::error(401, "usuario desativado"));
        }
        Auth::Ok(user)
    }

    fn discovery(&self) -> Value {
        let i = &self.cfg.issuer;
        json!({
            "issuer": i,
            "jwks_uri": format!("{i}/jwks"),
            "token_endpoint": format!("{i}/oauth/token"),
            "device_authorization_endpoint": format!("{i}/oauth/device"),
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:device_code"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "claims_supported": ["sub", "preferred_username", "groups", "openvnc_machine", "openvnc_perms", "openvnc_ask"],
        })
    }

    fn issue(&self, user: &str, machine: &str, via: &str, ip: IpAddr) -> Result<String, Response> {
        let st = self.store();
        let Some(eff) = st.effective(user, machine) else {
            self.rec(
                "central_ticket",
                &[
                    ("user", user),
                    ("machine", machine),
                    ("via", via),
                    ("ip", &ip.to_string()),
                    ("result", "negado"),
                ],
            );
            return Err(Response::error(403, "sem permissao para esta maquina"));
        };
        let groups = st.groups_of(user);
        let t = self
            .signer
            .ticket(&TicketReq {
                issuer: &self.cfg.issuer,
                audience: &self.cfg.client_id,
                user,
                groups: &groups,
                machine,
                perms: &eff.perms,
                ask: eff.ask,
                now: unix_now(),
                ttl: self.cfg.ticket_ttl,
            })
            .map_err(|_| Response::error(500, "falha ao emitir o ticket"))?;
        let perms = eff.perms.join(",");
        let ask = eff.ask.map(|a| a.to_string()).unwrap_or_default();
        self.rec(
            "central_ticket",
            &[
                ("user", user),
                ("machine", machine),
                ("perms", &perms),
                ("ask", &ask),
                ("via", via),
                ("ip", &ip.to_string()),
                ("result", "ok"),
            ],
        );
        Ok(t)
    }

    /// Atende uma requisicao (bloqueante: pode rodar Argon2).
    pub fn handle(&self, r: &Request) -> Response {
        let m = r.method.as_str();
        match (m, r.path.as_str()) {
            ("GET", "/.well-known/openid-configuration") => Response::json(200, &self.discovery()),
            ("GET", "/jwks") => Response::json(200, &self.signer.jwks()),
            ("GET", "/ca.pem") => Response::text(200, "application/x-pem-file", self.ca_pem.clone()),
            ("GET", "/health") => Response::json(200, &json!({"ok": true})),
            ("POST", "/api/login") => self.api_login(r),
            ("POST", "/api/logout") => {
                if let Some(tok) = r.header("authorization").and_then(|h| h.strip_prefix("Bearer ")) {
                    self.sessions.lock().unwrap().remove(&key_of(tok.trim()));
                }
                Response::json(200, &json!({"ok": true}))
            }
            ("GET", "/api/machines") => self.api_machines(r),
            ("POST", "/api/ticket") => self.api_ticket(r),
            ("POST", "/api/audit") => self.api_audit_in(r),
            ("GET", "/api/audit") => self.api_audit_out(r),
            ("POST", "/oauth/device") => self.device_start(r),
            ("POST", "/oauth/token") => self.device_token(r),
            ("GET", "/device") => self.device_page(r.query_get("user_code").unwrap_or_default(), None),
            ("POST", "/device") => self.device_submit(r),
            ("GET", "/") => Response::html(200, page("OpenVNC Central", "<p>Servidor central OpenVNC. Para aprovar um login, abra <a href=\"/device\">/device</a>.</p>")),
            (_, p) if known(p) => Response::error(405, "metodo nao permitido"),
            _ => Response::error(404, "nao encontrado"),
        }
    }

    fn json_body(r: &Request) -> Result<Value, Response> {
        serde_json::from_slice(&r.body).map_err(|_| Response::error(400, "JSON invalido"))
    }

    fn api_login(&self, r: &Request) -> Response {
        let v = match Self::json_body(r) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let user = v.get("user").and_then(Value::as_str).unwrap_or("");
        let pw = v.get("password").and_then(Value::as_str).unwrap_or("");
        if !valid_name(user) || pw.is_empty() || pw.len() > 1024 {
            return Response::error(400, "usuario ou senha ausentes");
        }
        if let Err(e) = self.check_password(user, pw, r.peer, "api") {
            return e;
        }
        let tok = random_token(32);
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, v| v.exp > now);
        if s.len() >= MAX_SESSIONS {
            return Response::error(503, "sessoes demais");
        }
        s.insert(
            key_of(&tok),
            Sess {
                user: user.to_owned(),
                exp: now + Duration::from_secs(self.cfg.session_ttl),
            },
        );
        Response::json(
            200,
            &json!({"session": tok, "user": user, "expires_in": self.cfg.session_ttl}),
        )
    }

    fn api_machines(&self, r: &Request) -> Response {
        let user = match self.session_user(r) {
            Auth::Ok(u) => u,
            Auth::Fail(e) => return e,
        };
        let st = self.store();
        let list: Vec<Value> = st
            .machines
            .iter()
            .filter_map(|(id, m)| {
                let e = st.effective(&user, id)?;
                Some(json!({
                    "id": id, "name": m.name, "address": m.address, "port": m.port,
                    "fingerprint": m.fingerprint.clone().unwrap_or_default(), "perms": e.perms,
                }))
            })
            .collect();
        Response::json(200, &json!({"user": user, "machines": list}))
    }

    fn api_ticket(&self, r: &Request) -> Response {
        let user = match self.session_user(r) {
            Auth::Ok(u) => u,
            Auth::Fail(e) => return e,
        };
        let v = match Self::json_body(r) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let machine = v.get("machine").and_then(Value::as_str).unwrap_or("");
        if !valid_name(machine) {
            return Response::error(400, "maquina invalida");
        }
        match self.issue(&user, machine, "api", r.peer) {
            Ok(t) => Response::json(
                200,
                &json!({"ticket": t, "expires_in": self.cfg.ticket_ttl}),
            ),
            Err(e) => e,
        }
    }

    /// `Authorization: Machine <id> <segredo>`.
    fn api_audit_in(&self, r: &Request) -> Response {
        let Some((id, secret)) = r
            .header("authorization")
            .and_then(|h| h.strip_prefix("Machine "))
            .and_then(|h| h.trim().split_once(' '))
        else {
            return Response::error(401, "credencial da maquina ausente");
        };
        let st = self.store();
        if !valid_name(id) || !st.machine_secret_ok(id, secret.trim()) {
            self.rec(
                "central_audit_in",
                &[
                    ("machine", if valid_name(id) { id } else { "?" }),
                    ("ip", &r.peer.to_string()),
                    ("result", "negado"),
                ],
            );
            return Response::error(401, "credencial da maquina invalida");
        }
        let txt = String::from_utf8_lossy(&r.body);
        let mut n = 0;
        for line in txt.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if line.len() > MAX_EVENT
                || serde_json::from_str::<Value>(line)
                    .map(|v| !v.is_object())
                    .unwrap_or(true)
            {
                continue;
            }
            self.rec(
                "remote",
                &[
                    ("machine", id),
                    ("ip", &r.peer.to_string()),
                    ("entry", line),
                ],
            );
            n += 1;
        }
        Response::json(200, &json!({"accepted": n}))
    }

    fn api_audit_out(&self, r: &Request) -> Response {
        let user = match self.session_user(r) {
            Auth::Ok(u) => u,
            Auth::Fail(e) => return e,
        };
        if !self.store().users.get(&user).is_some_and(|u| u.admin) {
            return Response::error(403, "apenas administradores");
        }
        let limit: usize = r
            .query_get("limit")
            .and_then(|l| l.parse().ok())
            .unwrap_or(200)
            .clamp(1, 5000);
        let txt = std::fs::read_to_string(self.cfg.audit_path()).unwrap_or_default();
        let lines: Vec<&str> = txt.lines().collect();
        let start = lines.len().saturating_sub(limit);
        let ev: Vec<Value> = lines[start..]
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        Response::json(200, &json!({"events": ev}))
    }

    fn device_start(&self, r: &Request) -> Response {
        let f = r.form();
        let get = |k: &str| {
            f.iter()
                .find(|(a, _)| a == k)
                .map(|(_, v)| v.as_str())
                .unwrap_or("")
        };
        let client_id = get("client_id");
        if client_id != self.cfg.client_id {
            return Response::json(400, &json!({"error": "invalid_client"}));
        }
        let Some(machine) = get("scope")
            .split(' ')
            .find_map(|s| s.strip_prefix(SCOPE_MACHINE))
        else {
            return Response::json(
                400,
                &json!({"error": "invalid_scope", "error_description": "escopo sem openvnc:machine:<id>"}),
            );
        };
        if !valid_name(machine) {
            return Response::json(400, &json!({"error": "invalid_scope"}));
        }
        let device_code = random_token(32);
        let user_code = {
            let raw = random_token(12)
                .to_ascii_uppercase()
                .replace(['-', '_', '0', 'O', '1', 'I'], "X");
            format!("{}-{}", &raw[..4], &raw[4..8])
        };
        let mut d = self.devices.lock().unwrap();
        let now = Instant::now();
        d.retain(|_, v| v.exp > now);
        if d.len() >= MAX_DEVICES {
            return Response::json(503, &json!({"error": "temporarily_unavailable"}));
        }
        d.insert(
            key_of(&device_code),
            Device {
                user_code: user_code.clone(),
                machine: machine.to_owned(),
                client_id: client_id.to_owned(),
                exp: now + DEVICE_TTL,
                approved: None,
                denied: false,
                last_poll: None,
            },
        );
        let i = &self.cfg.issuer;
        Response::json(
            200,
            &json!({
                "device_code": device_code, "user_code": user_code,
                "verification_uri": format!("{i}/device"),
                "verification_uri_complete": format!("{i}/device?user_code={user_code}"),
                "expires_in": DEVICE_TTL.as_secs(), "interval": DEVICE_INTERVAL,
            }),
        )
    }

    fn device_token(&self, r: &Request) -> Response {
        let f = r.form();
        let get = |k: &str| {
            f.iter()
                .find(|(a, _)| a == k)
                .map(|(_, v)| v.as_str())
                .unwrap_or("")
        };
        if get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
            return Response::json(400, &json!({"error": "unsupported_grant_type"}));
        }
        let k = key_of(get("device_code"));
        let (user, machine) = {
            let mut d = self.devices.lock().unwrap();
            let Some(dev) = d.get_mut(&k) else {
                return Response::json(400, &json!({"error": "expired_token"}));
            };
            if dev.client_id != get("client_id") {
                return Response::json(400, &json!({"error": "invalid_client"}));
            }
            if dev.exp < Instant::now() {
                d.remove(&k);
                return Response::json(400, &json!({"error": "expired_token"}));
            }
            if dev.denied {
                d.remove(&k);
                return Response::json(400, &json!({"error": "access_denied"}));
            }
            let Some(user) = dev.approved.clone() else {
                let fast = dev.last_poll.is_some_and(|t| {
                    t.elapsed() < Duration::from_millis(DEVICE_INTERVAL * 1000 - 500)
                });
                dev.last_poll = Some(Instant::now());
                let e = if fast {
                    "slow_down"
                } else {
                    "authorization_pending"
                };
                return Response::json(400, &json!({"error": e}));
            };
            let machine = dev.machine.clone();
            // codigo de uso unico
            d.remove(&k);
            (user, machine)
        };
        match self.issue(&user, &machine, "device", r.peer) {
            Ok(t) => Response::json(
                200,
                &json!({"id_token": t, "token_type": "Bearer", "expires_in": self.cfg.ticket_ttl}),
            ),
            Err(_) => Response::json(400, &json!({"error": "access_denied"})),
        }
    }

    fn device_page(&self, code: String, msg: Option<&str>) -> Response {
        let code = html_escape(
            &code
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .take(16)
                .collect::<String>(),
        );
        let m = msg
            .map(|m| format!("<p class=\"m\">{}</p>", html_escape(m)))
            .unwrap_or_default();
        Response::html(
            200,
            page(
                "Aprovar acesso",
                &format!(
                    "{m}<form method=\"post\" action=\"/device\">\
                     <label>Codigo<input name=\"user_code\" value=\"{code}\" required></label>\
                     <label>Usuario<input name=\"user\" autocomplete=\"username\" required></label>\
                     <label>Senha<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>\
                     <button name=\"action\" value=\"approve\">Aprovar</button> \
                     <button name=\"action\" value=\"deny\">Negar</button></form>"
                ),
            ),
        )
    }

    fn device_submit(&self, r: &Request) -> Response {
        let f = r.form();
        let get = |k: &str| {
            f.iter()
                .find(|(a, _)| a == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let code = get("user_code").trim().to_ascii_uppercase();
        let user = get("user").trim().to_owned();
        let pw = get("password");
        if !valid_name(&user) || pw.is_empty() {
            return self.device_page(code, Some("Informe usuario e senha."));
        }
        if let Err(e) = self.check_password(&user, &pw, r.peer, "device") {
            let msg = if e.status == 429 {
                "Muitas tentativas. Aguarde e tente de novo."
            } else {
                "Usuario ou senha invalidos."
            };
            return self.device_page(code, Some(msg));
        }
        let mut d = self.devices.lock().unwrap();
        let now = Instant::now();
        let Some(dev) = d
            .values_mut()
            .find(|v| v.user_code == code && v.exp > now && v.approved.is_none())
        else {
            return self.device_page(String::new(), Some("Codigo invalido ou expirado."));
        };
        if get("action") == "deny" {
            dev.denied = true;
            return Response::html(
                200,
                page(
                    "Acesso negado",
                    "<p>Pedido negado. Pode fechar esta janela.</p>",
                ),
            );
        }
        let machine = dev.machine.clone();
        if self.store().effective(&user, &machine).is_none() {
            dev.denied = true;
            drop(d);
            self.rec(
                "central_ticket",
                &[
                    ("user", &user),
                    ("machine", &machine),
                    ("via", "device"),
                    ("ip", &r.peer.to_string()),
                    ("result", "negado"),
                ],
            );
            return Response::html(
                403,
                page(
                    "Sem permissao",
                    "<p>Seu usuario nao tem acesso a esta maquina.</p>",
                ),
            );
        }
        dev.approved = Some(user);
        Response::html(
            200,
            page(
                "Acesso aprovado",
                &format!(
                    "<p>Acesso a <b>{}</b> aprovado. Pode fechar esta janela.</p>",
                    html_escape(&machine)
                ),
            ),
        )
    }
}

fn known(p: &str) -> bool {
    matches!(
        p,
        "/.well-known/openid-configuration"
            | "/jwks"
            | "/ca.pem"
            | "/health"
            | "/api/login"
            | "/api/logout"
            | "/api/machines"
            | "/api/ticket"
            | "/api/audit"
            | "/oauth/device"
            | "/oauth/token"
            | "/device"
            | "/"
    )
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{t}</title><style>body{{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}}\
         label{{display:block;margin:.6rem 0}}input{{display:block;width:100%;padding:.4rem;box-sizing:border-box}}\
         button{{padding:.5rem 1rem;margin-top:.6rem}}.m{{color:#a40}}</style></head>\
         <body><h1>{t}</h1>{body}</body></html>",
        t = html_escape(title)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloqueio_progressivo() {
        let mut l = Lockout::new(2);
        l.fail("u:a");
        l.fail("u:a");
        assert!(l.blocked("u:a").is_none());
        l.fail("u:a");
        let s = l.blocked("u:a").unwrap();
        assert!((25..=30).contains(&s), "{s}");
        l.fail("u:a");
        assert!(l.blocked("u:a").unwrap() > 30);
        for _ in 0..20 {
            l.fail("u:a");
        }
        assert!(l.blocked("u:a").unwrap() <= 900);
        l.ok("u:a");
        assert!(l.blocked("u:a").is_none());
    }
}
