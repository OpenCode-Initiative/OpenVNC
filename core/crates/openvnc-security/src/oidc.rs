//! Login SSO por OpenID Connect.
//!
//! - Cliente: fluxo de codigo de dispositivo (RFC 8628). O usuario aprova no
//!   navegador (Entra ID, Okta, Keycloak, Google...) e o cliente recebe um
//!   ID token, que vai como segredo do `AuthRequest`.
//! - Servidor: [`Verifier`] confere assinatura (RS256/ES256 pelas chaves
//!   JWKS do provedor), `iss`, `aud`, `exp`/`nbf`, grupos exigidos e recusa
//!   reuso do mesmo token.
//!
//! As chamadas HTTP sao bloqueantes; use em `spawn_blocking`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ring::signature;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Folga de relogio aceita em `exp`/`nbf`/`iat`.
const LEEWAY: u64 = 60;
/// Intervalo minimo entre buscas do JWKS (protege contra kid inventado).
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(60);

/// Erro de OIDC (mensagem sem segredos).
#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(m: impl Into<String>) -> Result<T, Error> {
    Err(Error(m.into()))
}

/// Cliente HTTP com as raizes publicas, as do sistema (CA corporativa
/// instalada) e, opcionalmente, uma CA extra (PEM).
pub fn http_agent(ca_pem: Option<&[u8]>) -> Result<ureq::Agent, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    if let Some(pem) = ca_pem {
        let mut n = 0;
        use rustls::pki_types::pem::PemObject;
        for c in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
            let c = c.map_err(|e| Error(format!("CA OIDC invalida: {e}")))?;
            roots
                .add(c)
                .map_err(|e| Error(format!("CA OIDC invalida: {e}")))?;
            n += 1;
        }
        if n == 0 {
            return err("CA OIDC sem certificados");
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error(e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls))
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .build())
}

/// So HTTPS (ou http para loopback, util em testes).
fn check_url(u: &str) -> Result<(), Error> {
    let ok = u.starts_with("https://")
        || u.starts_with("http://127.0.0.1")
        || u.starts_with("http://localhost")
        || u.starts_with("http://[::1]");
    if ok {
        Ok(())
    } else {
        err(format!("URL OIDC precisa ser https: {u}"))
    }
}

fn get_json(agent: &ureq::Agent, url: &str) -> Result<Value, Error> {
    check_url(url)?;
    agent
        .get(url)
        .call()
        .map_err(|e| Error(format!("GET {url}: {e}")))?
        .into_json()
        .map_err(|e| Error(format!("GET {url}: JSON invalido: {e}")))
}

/// Endpoints do provedor (`.well-known/openid-configuration`).
#[derive(Debug, Clone)]
pub struct Discovery {
    /// Emissor declarado (tem que bater com o configurado).
    pub issuer: String,
    /// Chaves publicas.
    pub jwks_uri: String,
    /// Inicio do fluxo de dispositivo (pode faltar).
    pub device_authorization_endpoint: Option<String>,
    /// Troca do codigo por tokens.
    pub token_endpoint: String,
}

impl Discovery {
    /// Busca e confere que o `issuer` declarado e o esperado.
    pub fn fetch(agent: &ureq::Agent, issuer: &str) -> Result<Self, Error> {
        let issuer = issuer.trim_end_matches('/');
        let v = get_json(agent, &format!("{issuer}/.well-known/openid-configuration"))?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let declared = s("issuer").ok_or_else(|| Error("descoberta sem issuer".into()))?;
        if declared.trim_end_matches('/') != issuer {
            return err(format!("issuer divergente: {declared}"));
        }
        let d = Discovery {
            issuer: declared,
            jwks_uri: s("jwks_uri").ok_or_else(|| Error("descoberta sem jwks_uri".into()))?,
            device_authorization_endpoint: s("device_authorization_endpoint"),
            token_endpoint: s("token_endpoint")
                .ok_or_else(|| Error("descoberta sem token_endpoint".into()))?,
        };
        check_url(&d.jwks_uri)?;
        check_url(&d.token_endpoint)?;
        if let Some(u) = &d.device_authorization_endpoint {
            check_url(u)?;
        }
        Ok(d)
    }
}

/// Chave publica de verificacao.
#[derive(Clone)]
enum Key {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256(Vec<u8>),
}

/// Conjunto de chaves por `kid`.
#[derive(Clone, Default)]
pub struct Jwks(HashMap<String, Key>);

impl Jwks {
    /// Interpreta um documento JWKS (ignora chaves de tipo nao suportado).
    pub fn parse(v: &Value) -> Self {
        let mut m = HashMap::new();
        let keys = v
            .get("keys")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for k in keys {
            let s = |f: &str| k.get(f).and_then(Value::as_str);
            if s("use").is_some_and(|u| u != "sig") {
                continue;
            }
            let kid = s("kid").unwrap_or("").to_owned();
            let d = |f: &str| s(f).and_then(|x| B64.decode(x).ok());
            let key = match s("kty") {
                Some("RSA") => match (d("n"), d("e")) {
                    (Some(n), Some(e)) => Key::Rsa { n, e },
                    _ => continue,
                },
                Some("EC") if s("crv") == Some("P-256") => match (d("x"), d("y")) {
                    (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
                        let mut p = vec![4u8];
                        p.extend(x);
                        p.extend(y);
                        Key::P256(p)
                    }
                    _ => continue,
                },
                _ => continue,
            };
            m.insert(kid, key);
        }
        Jwks(m)
    }

    /// Quantidade de chaves.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Vazio?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// O que o servidor exige do token.
#[derive(Debug, Clone)]
pub struct Policy {
    /// `iss` esperado.
    pub issuer: String,
    /// `aud` esperado (client id).
    pub audience: String,
    /// Claim com o nome do usuario (ex.: `preferred_username`, `email`, `upn`).
    pub user_claim: String,
    /// Claim com os grupos (lista de strings).
    pub groups_claim: String,
    /// Se nao vazio, o usuario precisa estar em pelo menos um destes grupos.
    pub allowed_groups: Vec<String>,
    /// Servidor central OpenVNC: id desta maquina. Quando definido, o token
    /// precisa trazer `openvnc_machine` igual a ele e a lista
    /// `openvnc_perms` (ticket emitido pelo servidor central).
    pub machine: Option<String>,
}

/// Claim do servidor central com o id da maquina do ticket.
pub const CLAIM_MACHINE: &str = "openvnc_machine";
/// Claim do servidor central com as permissoes da sessao.
pub const CLAIM_PERMS: &str = "openvnc_perms";
/// Claim do servidor central: `true` exige aprovacao do usuario local.
pub const CLAIM_ASK: &str = "openvnc_ask";
/// Prefixo do escopo que pede um ticket para uma maquina no fluxo de
/// codigo de dispositivo (`openvnc:machine:<id>`).
pub const SCOPE_MACHINE: &str = "openvnc:machine:";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Token decodificado e verificado.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Valor do `user_claim`.
    pub user: String,
    /// `exp`.
    pub exp: u64,
    /// `openvnc_machine` (ticket do servidor central).
    pub machine: Option<String>,
    /// `openvnc_perms` (ticket do servidor central).
    pub perms: Option<Vec<String>>,
    /// `openvnc_ask` (ticket do servidor central).
    pub ask: Option<bool>,
    /// Chave de reuso: `iss` + `jti` quando ha `jti`; senao o SHA-256 de
    /// `cabecalho.payload` (nunca da assinatura, que e maleavel no ES256).
    replay_key: [u8; 32],
}

/// Chave do cache de reuso. A assinatura fica de fora: no ECDSA, `(r, s)` e
/// `(r, n - s)` sao ambas validas, e um hash do token inteiro deixaria
/// reapresentar o mesmo ticket com a assinatura trocada.
fn replay_key(iss: &str, jti: Option<&str>, signed: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    match jti {
        Some(j) => {
            h.update(b"jti\0");
            h.update(iss.trim_end_matches('/').as_bytes());
            h.update(b"\0");
            h.update(j.as_bytes());
        }
        None => {
            h.update(b"msg\0");
            h.update(signed);
        }
    }
    h.finalize().into()
}

/// Verifica o JWT contra as chaves e a politica, no instante `t`.
/// `Err(None)` indica `kid` desconhecido (vale buscar o JWKS de novo).
fn verify_at(token: &str, jwks: &Jwks, p: &Policy, t: u64) -> Result<Identity, Option<Error>> {
    let bad = |m: &str| Some(Error(m.into()));
    let mut parts = token.split('.');
    let (Some(h), Some(b), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("token nao e um JWT"));
    };
    let header: Value = B64
        .decode(h)
        .ok()
        .and_then(|x| serde_json::from_slice(&x).ok())
        .ok_or_else(|| bad("cabecalho JWT invalido").unwrap())?;
    let sig = B64.decode(s).map_err(|_| bad("assinatura invalida"))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
    let key = jwks.0.get(kid).ok_or(None)?;
    let msg = &token.as_bytes()[..h.len() + 1 + b.len()];
    // o algoritmo vem da chave, nunca so do cabecalho (evita "alg: none" e troca de algoritmo)
    let ok = match (alg, key) {
        ("RS256", Key::Rsa { n, e }) => signature::RsaPublicKeyComponents { n, e }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, &sig)
            .is_ok(),
        ("ES256", Key::P256(pt)) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, pt)
                .verify(msg, &sig)
                .is_ok()
        }
        _ => return Err(bad("algoritmo nao aceito para a chave")),
    };
    if !ok {
        return Err(bad("assinatura nao confere"));
    }
    let c: Value = B64
        .decode(b)
        .ok()
        .and_then(|x| serde_json::from_slice(&x).ok())
        .ok_or_else(|| bad("claims invalidas").unwrap())?;
    let num = |k: &str| c.get(k).and_then(Value::as_u64);
    let iss = c.get("iss").and_then(Value::as_str).unwrap_or("");
    if iss.trim_end_matches('/') != p.issuer.trim_end_matches('/') {
        return Err(bad("iss nao confere"));
    }
    let aud_ok = match c.get("aud") {
        Some(Value::String(a)) => *a == p.audience,
        Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(&p.audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(bad("aud nao confere"));
    }
    if let Some(azp) = c.get("azp").and_then(Value::as_str) {
        if azp != p.audience {
            return Err(bad("azp nao confere"));
        }
    }
    let exp = num("exp").ok_or_else(|| bad("token sem exp").unwrap())?;
    if exp + LEEWAY < t {
        return Err(bad("token expirado"));
    }
    if num("nbf").is_some_and(|n| n > t + LEEWAY) || num("iat").is_some_and(|n| n > t + LEEWAY) {
        return Err(bad("token ainda nao valido"));
    }
    if !p.allowed_groups.is_empty() {
        let groups: Vec<&str> = c
            .get(&p.groups_claim)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if !p
            .allowed_groups
            .iter()
            .any(|g| groups.contains(&g.as_str()))
        {
            return Err(bad("usuario fora dos grupos permitidos"));
        }
    }
    let machine = c
        .get(CLAIM_MACHINE)
        .and_then(Value::as_str)
        .map(str::to_owned);
    let perms: Option<Vec<String>> = c.get(CLAIM_PERMS).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    });
    let jti = c
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty() && j.len() <= 256);
    if let Some(want) = &p.machine {
        if machine.as_deref() != Some(want.as_str()) {
            return Err(bad("ticket emitido para outra maquina"));
        }
        if perms.is_none() {
            return Err(bad("ticket sem permissoes"));
        }
        // o servidor central sempre emite jti; sem ele nao ha reuso confiavel
        if jti.is_none() {
            return Err(bad("ticket sem jti"));
        }
    }
    let user = c
        .get(&p.user_claim)
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty() && u.len() <= 256 && !u.chars().any(char::is_control))
        .ok_or_else(|| bad("token sem usuario valido").unwrap())?;
    Ok(Identity {
        user: user.to_owned(),
        exp,
        machine,
        perms,
        ask: c.get(CLAIM_ASK).and_then(Value::as_bool),
        replay_key: replay_key(iss, jti, msg),
    })
}

/// Verifica `token` contra chaves ja conhecidas no instante `t` (sem rede e
/// sem controle de reuso). Usado em testes e ferramentas.
pub fn verify_offline(token: &str, jwks: &Jwks, p: &Policy, t: u64) -> Result<Identity, Error> {
    verify_at(token, jwks, p, t)
        .map_err(|e| e.unwrap_or_else(|| Error("chave (kid) desconhecida".into())))
}

struct VerifierState {
    jwks: Jwks,
    fetched: Option<Instant>,
    /// chave de reuso (ver [`replay_key`]) -> exp (recusa reuso).
    seen: HashMap<[u8; 32], u64>,
}

/// Verificador do servidor (compartilhavel entre conexoes).
pub struct Verifier {
    policy: Policy,
    /// Vinculo por host no modo SSO generico (ver [`Verifier::require_host_binding`]).
    host_binding: Option<String>,
    agent: ureq::Agent,
    state: Mutex<VerifierState>,
}

impl Verifier {
    /// Cria sem rede; as chaves sao buscadas no primeiro uso.
    pub fn new(policy: Policy, ca_pem: Option<&[u8]>) -> Result<Self, Error> {
        check_url(&policy.issuer)?;
        // vinculo por host tambem pode vir do ambiente, sem mudar a configuracao
        let host_binding = std::env::var(ENV_HOST_BINDING)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        if policy.machine.is_none() && host_binding.is_none() {
            // sem tracing nesta crate: so stderr
            eprintln!(
                "aviso: SSO generico sem vinculo por host: um ID token com aud \"{}\" vale em \
                 qualquer host com a mesma audiencia (ver docs/security.md; defina {ENV_HOST_BINDING})",
                policy.audience
            );
        }
        Ok(Self {
            policy,
            host_binding,
            agent: http_agent(ca_pem)?,
            state: Mutex::new(VerifierState {
                jwks: Jwks::default(),
                fetched: None,
                seen: HashMap::new(),
            }),
        })
    }

    /// Politica configurada.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Exige vinculo por host no modo SSO generico: o token precisa trazer
    /// `openvnc_machine` igual a `id` ou ter `id` (ou `<audience>:<id>`)
    /// entre os valores de `aud`. Sem isso, um token emitido para um host
    /// pode ser reapresentado em outro que aceite a mesma audiencia.
    pub fn require_host_binding(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.host_binding = Some(id.trim().to_owned()).filter(|s| !s.is_empty());
        self
    }

    fn refresh(&self) -> Result<(), Error> {
        {
            let st = self.state.lock().unwrap();
            if st.fetched.is_some_and(|t| t.elapsed() < JWKS_MIN_REFRESH) {
                return Ok(());
            }
        }
        let d = Discovery::fetch(&self.agent, &self.policy.issuer)?;
        let jwks = Jwks::parse(&get_json(&self.agent, &d.jwks_uri)?);
        let mut st = self.state.lock().unwrap();
        st.jwks = jwks;
        st.fetched = Some(Instant::now());
        Ok(())
    }

    /// Verifica o ID token (bloqueante: pode buscar o JWKS).
    pub fn verify(&self, token: &[u8]) -> Result<Identity, Error> {
        let token = std::str::from_utf8(token).map_err(|_| Error("token nao e UTF-8".into()))?;
        let t = now();
        let first = {
            let st = self.state.lock().unwrap();
            if st.fetched.is_none() {
                None
            } else {
                Some(verify_at(token, &st.jwks, &self.policy, t))
            }
        };
        let r = match first {
            Some(Err(None)) | None => {
                self.refresh()?;
                let st = self.state.lock().unwrap();
                verify_at(token, &st.jwks, &self.policy, t)
            }
            Some(r) => r,
        };
        let id = r.map_err(|e| e.unwrap_or_else(|| Error("chave (kid) desconhecida".into())))?;
        if let Some(want) = &self.host_binding {
            if !host_bound(token, &self.policy.audience, want) {
                return err("token sem vinculo com este host");
            }
        }
        let mut st = self.state.lock().unwrap();
        st.seen.retain(|_, exp| *exp + LEEWAY >= t);
        if st.seen.insert(id.replay_key, id.exp).is_some() {
            return err("token ja usado (reuso recusado)");
        }
        Ok(id)
    }
}

/// Variavel de ambiente com o id deste host para o vinculo por host no
/// modo SSO generico (ver [`Verifier::require_host_binding`]).
pub const ENV_HOST_BINDING: &str = "OPENVNC_OIDC_HOST_ID";

/// O token (ja verificado) esta vinculado ao host `id`?
fn host_bound(token: &str, audience: &str, id: &str) -> bool {
    let Some(c) = token
        .split('.')
        .nth(1)
        .and_then(|b| B64.decode(b).ok())
        .and_then(|x| serde_json::from_slice::<Value>(&x).ok())
    else {
        return false;
    };
    if c.get(CLAIM_MACHINE).and_then(Value::as_str) == Some(id) {
        return true;
    }
    let scoped = format!("{audience}:{id}");
    let hit = |a: &str| a == id || a == scoped;
    match c.get("aud") {
        Some(Value::String(a)) => hit(a),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).any(hit),
        _ => false,
    }
}

/// Falhas de rede seguidas aceitas na espera do token.
const MAX_NET_FAILS: u32 = 5;

fn warn_retry(n: u32, e: &ureq::Error) {
    // sem tracing nesta crate: so stderr, e a mensagem nao traz segredos
    eprintln!(
        "aviso: falha de rede ao buscar o token ({n}/{MAX_NET_FAILS}), tentando de novo: {e}"
    );
}

/// Codigo para o usuario aprovar no navegador.
#[derive(Debug, Clone)]
pub struct DeviceCode {
    /// Codigo curto que o usuario digita.
    pub user_code: String,
    /// Pagina de aprovacao.
    pub verification_uri: String,
    /// Pagina ja com o codigo (quando o provedor fornece).
    pub verification_uri_complete: Option<String>,
    /// Validade, em segundos.
    pub expires_in: u64,
}

/// Login por codigo de dispositivo. `show` recebe o codigo para exibir;
/// `cancel` e consultado a cada espera. Devolve o ID token.
pub fn device_login(
    issuer: &str,
    client_id: &str,
    scope: &str,
    ca_pem: Option<&[u8]>,
    show: &mut dyn FnMut(&DeviceCode),
    cancel: &dyn Fn() -> bool,
) -> Result<String, Error> {
    let agent = http_agent(ca_pem)?;
    let d = Discovery::fetch(&agent, issuer)?;
    let Some(dev_url) = &d.device_authorization_endpoint else {
        return err("o provedor nao oferece login por codigo de dispositivo");
    };
    let scope = if scope.split(' ').any(|s| s == "openid") {
        scope.to_owned()
    } else {
        format!("openid {scope}").trim().to_owned()
    };
    let v: Value = agent
        .post(dev_url)
        .send_form(&[("client_id", client_id), ("scope", &scope)])
        .map_err(|e| Error(format!("inicio do login: {e}")))?
        .into_json()
        .map_err(|e| Error(format!("inicio do login: {e}")))?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let device_code = s("device_code").ok_or_else(|| Error("resposta sem device_code".into()))?;
    let code = DeviceCode {
        user_code: s("user_code").ok_or_else(|| Error("resposta sem user_code".into()))?,
        verification_uri: s("verification_uri")
            .or_else(|| s("verification_url"))
            .ok_or_else(|| Error("resposta sem verification_uri".into()))?,
        verification_uri_complete: s("verification_uri_complete"),
        expires_in: v.get("expires_in").and_then(Value::as_u64).unwrap_or(600),
    };
    show(&code);
    let mut interval = v
        .get("interval")
        .and_then(Value::as_u64)
        .unwrap_or(5)
        .max(1);
    let deadline = Instant::now() + Duration::from_secs(code.expires_in.min(1800));
    // falhas de rede seguidas toleradas (ex.: timeout isolado, os error 10060)
    let mut net_fails = 0u32;
    loop {
        for _ in 0..interval * 10 {
            if cancel() {
                return err("login cancelado");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if Instant::now() > deadline {
            return err("o codigo expirou");
        }
        let r = agent.post(&d.token_endpoint).send_form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &device_code),
            ("client_id", client_id),
        ]);
        let body: Value = match r {
            Ok(resp) => resp.into_json().map_err(|e| Error(e.to_string()))?,
            Err(ureq::Error::Status(_, resp)) => resp.into_json().unwrap_or(Value::Null),
            Err(e) => {
                net_fails += 1;
                if net_fails > MAX_NET_FAILS {
                    return err(format!("token: {e}"));
                }
                warn_retry(net_fails, &e);
                continue;
            }
        };
        net_fails = 0;
        if let Some(t) = body.get("id_token").and_then(Value::as_str) {
            return Ok(t.to_owned());
        }
        match body.get("error").and_then(Value::as_str) {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some("access_denied") => return err("login negado no provedor"),
            Some("expired_token") => return err("o codigo expirou"),
            Some(e) => return err(format!("provedor recusou: {e}")),
            None => return err("resposta sem id_token (o escopo inclui openid?)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn policy() -> Policy {
        Policy {
            issuer: "https://idp.test/realms/ti".into(),
            audience: "openvnc".into(),
            user_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            allowed_groups: vec![],
            machine: None,
        }
    }

    fn setup() -> (EcdsaKeyPair, Jwks) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pt = kp.public_key().as_ref();
        let jwks = Jwks::parse(&serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig",
            "x": B64.encode(&pt[1..33]), "y": B64.encode(&pt[33..65]),
        }]}));
        (kp, jwks)
    }

    fn sign(kp: &EcdsaKeyPair, header: Value, claims: Value) -> String {
        let m = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = kp.sign(&SystemRandom::new(), m.as_bytes()).unwrap();
        format!("{m}.{}", B64.encode(sig.as_ref()))
    }

    fn claims(t: u64) -> Value {
        serde_json::json!({
            "iss": "https://idp.test/realms/ti", "aud": "openvnc", "azp": "openvnc",
            "exp": t + 300, "iat": t, "preferred_username": "alice", "groups": ["suporte"],
        })
    }

    #[test]
    fn aceita_token_valido_e_recusa_adulterado() {
        let (kp, jwks) = setup();
        let t = 1_800_000_000;
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        let tok = sign(&kp, h.clone(), claims(t));
        assert_eq!(verify_at(&tok, &jwks, &policy(), t).unwrap().user, "alice");
        // troca o payload mantendo a assinatura
        let mut c = claims(t);
        c["preferred_username"] = "root".into();
        let forged = format!(
            "{}.{}.{}",
            tok.split('.').next().unwrap(),
            B64.encode(c.to_string()),
            tok.split('.').nth(2).unwrap()
        );
        assert!(verify_at(&forged, &jwks, &policy(), t).is_err());
    }

    #[test]
    fn recusa_alg_none_iss_aud_exp_kid() {
        let (kp, jwks) = setup();
        let t = 1_800_000_000;
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        let none = format!(
            "{}.{}.",
            B64.encode(r#"{"alg":"none","kid":"k1"}"#),
            B64.encode(claims(t).to_string())
        );
        assert!(verify_at(&none, &jwks, &policy(), t).is_err());
        for (k, v) in [
            ("iss", Value::from("https://outro.test")),
            ("aud", Value::from("outro")),
            ("azp", Value::from("outro")),
            ("exp", Value::from(t - 1000)),
            ("nbf", Value::from(t + 1000)),
        ] {
            let mut c = claims(t);
            c[k] = v;
            assert!(
                verify_at(&sign(&kp, h.clone(), c), &jwks, &policy(), t).is_err(),
                "{k}"
            );
        }
        let other = sign(
            &kp,
            serde_json::json!({"alg": "ES256", "kid": "x"}),
            claims(t),
        );
        assert!(matches!(verify_at(&other, &jwks, &policy(), t), Err(None)));
        let rs = sign(
            &kp,
            serde_json::json!({"alg": "RS256", "kid": "k1"}),
            claims(t),
        );
        assert!(verify_at(&rs, &jwks, &policy(), t).is_err());
    }

    #[test]
    fn grupos_exigidos() {
        let (kp, jwks) = setup();
        let t = 1_800_000_000;
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        let tok = sign(&kp, h, claims(t));
        let mut p = policy();
        p.allowed_groups = vec!["admins".into()];
        assert!(verify_at(&tok, &jwks, &p, t).is_err());
        p.allowed_groups.push("suporte".into());
        assert!(verify_at(&tok, &jwks, &p, t).is_ok());
    }

    #[test]
    fn ticket_central_maquina_e_permissoes() {
        let (kp, jwks) = setup();
        let t = 1_800_000_000;
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        let mut c = claims(t);
        c[CLAIM_MACHINE] = "pc-01".into();
        c[CLAIM_PERMS] = serde_json::json!(["view", "control"]);
        c[CLAIM_ASK] = true.into();
        c["jti"] = "t1".into();
        let tok = sign(&kp, h.clone(), c.clone());
        let mut p = policy();
        p.machine = Some("pc-01".into());
        let id = verify_at(&tok, &jwks, &p, t).unwrap();
        assert_eq!(id.machine.as_deref(), Some("pc-01"));
        assert_eq!(id.perms.unwrap(), vec!["view", "control"]);
        assert_eq!(id.ask, Some(true));
        p.machine = Some("pc-02".into());
        assert!(verify_at(&tok, &jwks, &p, t).is_err());
        // token comum (sem claims do central) nao vale quando a maquina e exigida
        let plain = sign(&kp, h, claims(t));
        p.machine = Some("pc-01".into());
        assert!(verify_at(&plain, &jwks, &p, t).is_err());
        assert!(verify_at(&plain, &jwks, &policy(), t)
            .unwrap()
            .perms
            .is_none());
    }

    #[test]
    fn verifier_recusa_reuso_do_token() {
        let (kp, jwks) = setup();
        let v = Verifier::new(policy(), None).unwrap();
        {
            let mut st = v.state.lock().unwrap();
            st.jwks = jwks;
            st.fetched = Some(Instant::now());
        }
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        let tok = sign(&kp, h, claims(now()));
        assert_eq!(v.verify(tok.as_bytes()).unwrap().user, "alice");
        assert!(v.verify(tok.as_bytes()).is_err());
    }

    fn verifier(p: Policy, jwks: Jwks) -> Verifier {
        let v = Verifier::new(p, None).unwrap();
        {
            let mut st = v.state.lock().unwrap();
            st.jwks = jwks;
            st.fetched = Some(Instant::now());
        }
        v
    }

    /// Troca `s` por `n - s` (assinatura ES256 maleavel, ainda valida).
    fn malleate(tok: &str) -> String {
        // ordem do grupo P-256
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ];
        let (m, s) = tok.rsplit_once('.').unwrap();
        let mut sig = B64.decode(s).unwrap();
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = N[i] as i16 - sig[32 + i] as i16 - borrow;
            borrow = (d < 0) as i16;
            sig[32 + i] = (d + 256 * borrow) as u8;
        }
        format!("{m}.{}", B64.encode(sig))
    }

    #[test]
    fn reuso_com_assinatura_maleavel_e_recusado() {
        let (kp, jwks) = setup();
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        // sem jti (IdP generico): chave e cabecalho.payload
        let v = verifier(policy(), jwks.clone());
        let tok = sign(&kp, h.clone(), claims(now()));
        let alt = malleate(&tok);
        assert_ne!(tok, alt);
        assert!(verify_offline(&alt, &jwks, &policy(), now()).is_ok());
        assert!(v.verify(tok.as_bytes()).is_ok());
        assert!(v.verify(alt.as_bytes()).is_err());
        // com jti: chave e iss + jti, mesmo reassinado com outro payload
        let mut c = claims(now());
        c["jti"] = "abc".into();
        assert!(v.verify(sign(&kp, h.clone(), c.clone()).as_bytes()).is_ok());
        c["iat"] = (now() - 1).into();
        assert!(v.verify(sign(&kp, h, c).as_bytes()).is_err());
    }

    #[test]
    fn ticket_central_exige_jti() {
        let (kp, jwks) = setup();
        let t = 1_800_000_000;
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        let mut c = claims(t);
        c[CLAIM_MACHINE] = "pc-01".into();
        c[CLAIM_PERMS] = serde_json::json!(["view"]);
        let mut p = policy();
        p.machine = Some("pc-01".into());
        assert!(verify_at(&sign(&kp, h.clone(), c.clone()), &jwks, &p, t).is_err());
        c["jti"] = "x1".into();
        assert!(verify_at(&sign(&kp, h, c), &jwks, &p, t).is_ok());
    }

    #[test]
    fn vinculo_por_host_no_sso_generico() {
        let (kp, jwks) = setup();
        let h = serde_json::json!({"alg": "ES256", "kid": "k1"});
        let v = verifier(policy(), jwks).require_host_binding("pc-01");
        // token generico sem vinculo: recusado
        assert!(v
            .verify(sign(&kp, h.clone(), claims(now())).as_bytes())
            .is_err());
        // claim openvnc_machine
        let mut c = claims(now());
        c[CLAIM_MACHINE] = "pc-01".into();
        assert!(v.verify(sign(&kp, h.clone(), c).as_bytes()).is_ok());
        // aud por maquina
        let mut c = claims(now());
        c["aud"] = serde_json::json!(["openvnc", "openvnc:pc-01"]);
        assert!(v.verify(sign(&kp, h.clone(), c).as_bytes()).is_ok());
        // outro host
        let mut c = claims(now());
        c["aud"] = serde_json::json!(["openvnc", "openvnc:pc-02"]);
        assert!(v.verify(sign(&kp, h, c).as_bytes()).is_err());
    }
}
