//! Tickets: JWT ES256 assinados com a chave do servidor central.

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use openvnc_security::oidc::{CLAIM_ASK, CLAIM_MACHINE, CLAIM_PERMS};

/// Assinador.
pub struct Signer {
    kp: EcdsaKeyPair,
    kid: String,
    rng: SystemRandom,
}

/// Dados de um ticket.
pub struct TicketReq<'a> {
    /// `iss`.
    pub issuer: &'a str,
    /// `aud`.
    pub audience: &'a str,
    /// Usuario.
    pub user: &'a str,
    /// Grupos.
    pub groups: &'a [String],
    /// Maquina.
    pub machine: &'a str,
    /// Permissoes.
    pub perms: &'a [String],
    /// Sobreposicao de aprovacao.
    pub ask: Option<bool>,
    /// Instante de emissao.
    pub now: u64,
    /// Validade em segundos.
    pub ttl: u64,
}

/// Bytes aleatorios em base64url.
pub fn random_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut b)
        .expect("gerador aleatorio do sistema");
    B64.encode(b)
}

impl Signer {
    /// A partir do PKCS#8.
    pub fn new(pkcs8: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
            .map_err(|_| anyhow!("chave de assinatura invalida"))?;
        let kid = B64.encode(&Sha256::digest(kp.public_key().as_ref())[..12]);
        Ok(Self { kp, kid, rng })
    }

    /// Conjunto JWKS publico.
    pub fn jwks(&self) -> Value {
        let pt = self.kp.public_key().as_ref();
        json!({"keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid,
            "x": B64.encode(&pt[1..33]), "y": B64.encode(&pt[33..65]),
        }]})
    }

    /// Assina claims arbitrarias.
    pub fn sign(&self, claims: &Value) -> Result<String> {
        let h = json!({"alg": "ES256", "typ": "JWT", "kid": self.kid});
        let m = format!("{}.{}", B64.encode(h.to_string()), B64.encode(claims.to_string()));
        let sig = self
            .kp
            .sign(&self.rng, m.as_bytes())
            .map_err(|_| anyhow!("falha ao assinar"))?;
        Ok(format!("{m}.{}", B64.encode(sig.as_ref())))
    }

    /// Emite um ticket.
    pub fn ticket(&self, r: &TicketReq<'_>) -> Result<String> {
        let mut c = json!({
            "iss": r.issuer, "aud": r.audience, "azp": r.audience,
            "sub": r.user, "preferred_username": r.user, "groups": r.groups,
            "iat": r.now, "nbf": r.now, "exp": r.now + r.ttl,
            "jti": random_token(16),
            CLAIM_MACHINE: r.machine, CLAIM_PERMS: r.perms,
        });
        if let Some(a) = r.ask {
            c[CLAIM_ASK] = Value::Bool(a);
        }
        self.sign(&c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvnc_security::oidc::{verify_offline, Jwks, Policy};

    fn setup() -> (Signer, Jwks) {
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .unwrap();
        let s = Signer::new(doc.as_ref()).unwrap();
        let j = Jwks::parse(&s.jwks());
        (s, j)
    }

    fn policy(machine: &str) -> Policy {
        Policy {
            issuer: "https://central.test:8443".into(),
            audience: "openvnc".into(),
            user_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            allowed_groups: vec![],
            machine: Some(machine.into()),
        }
    }

    fn req<'a>(perms: &'a [String], groups: &'a [String], now: u64) -> TicketReq<'a> {
        TicketReq {
            issuer: "https://central.test:8443",
            audience: "openvnc",
            user: "alice",
            groups,
            machine: "pc-01",
            perms,
            ask: Some(false),
            now,
            ttl: 120,
        }
    }

    #[test]
    fn ticket_valido_maquina_errada_expirado_adulterado() {
        let (s, j) = setup();
        let perms = vec!["view".to_string(), "control".to_string()];
        let groups = vec!["suporte".to_string()];
        let t = 1_900_000_000;
        let tk = s.ticket(&req(&perms, &groups, t)).unwrap();
        let id = verify_offline(&tk, &j, &policy("pc-01"), t + 1).unwrap();
        assert_eq!(id.user, "alice");
        assert_eq!(id.machine.as_deref(), Some("pc-01"));
        assert_eq!(id.perms.as_deref(), Some(&perms[..]));
        assert_eq!(id.ask, Some(false));
        // maquina errada
        let e = verify_offline(&tk, &j, &policy("pc-02"), t + 1).unwrap_err();
        assert!(e.0.contains("outra maquina"), "{e}");
        // expirado (ttl 120 + folga 60)
        assert!(verify_offline(&tk, &j, &policy("pc-01"), t + 400).is_err());
        // adulterado: troca as claims mantendo a assinatura
        let mut parts: Vec<&str> = tk.split('.').collect();
        let forged = B64.encode(
            json!({"iss": "https://central.test:8443", "aud": "openvnc", "exp": t + 100,
                   "preferred_username": "mallory", "openvnc_machine": "pc-01",
                   "openvnc_perms": ["view", "control", "files"]})
            .to_string(),
        );
        parts[1] = &forged;
        assert!(verify_offline(&parts.join("."), &j, &policy("pc-01"), t + 1).is_err());
        // outra chave
        let (_, j2) = setup();
        assert!(verify_offline(&tk, &j2, &policy("pc-01"), t + 1).is_err());
        // jti unico por ticket
        let tk2 = s.ticket(&req(&perms, &groups, t)).unwrap();
        assert_ne!(tk, tk2);
    }
}
