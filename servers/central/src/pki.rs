//! CA propria, certificado HTTPS e chave de assinatura dos tickets.
//!
//! Arquivos em `state_dir`: `ca.pem` (publico, exportavel), `ca.key`,
//! `tls.pem` (cadeia), `tls.key`, `tls.names` e `signing.key` (PKCS#8 P-256
//! em base64). Chaves privadas sao gravadas com permissao restrita.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::store::write_atomic;

const CA_CN: &str = "OpenVNC Central CA";

fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_CN);
    dn.push(DnType::OrganizationName, "OpenVNC");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2045, 1, 1);
    p
}

/// Material carregado.
pub struct Pki {
    /// CA em PEM.
    pub ca_pem: String,
    /// Cadeia HTTPS em PEM (folha + CA).
    pub tls_chain_pem: String,
    /// Chave HTTPS em PEM.
    pub tls_key_pem: String,
    /// Chave de assinatura (PKCS#8 DER).
    pub signing_pkcs8: Vec<u8>,
}

/// Grava arquivo privado (0600 no Unix).
pub fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    write_atomic(p, data, true)
}

/// Garante a CA, a folha HTTPS para `names` e a chave de assinatura.
/// A folha e refeita quando os nomes mudam.
pub fn ensure(dir: &Path, names: &[String]) -> Result<Pki> {
    std::fs::create_dir_all(dir).with_context(|| format!("criando {}", dir.display()))?;
    let ca_key_p = dir.join("ca.key");
    let ca_pem_p = dir.join("ca.pem");
    let ca_kp = if ca_key_p.exists() {
        KeyPair::from_pem(&std::fs::read_to_string(&ca_key_p)?).context("ca.key invalida")?
    } else {
        let kp = KeyPair::generate()?;
        write_private(&ca_key_p, kp.serialize_pem().as_bytes())?;
        let _ = std::fs::remove_file(&ca_pem_p);
        let _ = std::fs::remove_file(dir.join("tls.names"));
        kp
    };
    // a CA e refeita de forma deterministica (mesmo DN e chave) para assinar
    let ca_cert = ca_params().self_signed(&ca_kp)?;
    if !ca_pem_p.exists() {
        write_atomic(&ca_pem_p, ca_cert.pem().as_bytes(), false)?;
    }
    let ca_pem = std::fs::read_to_string(&ca_pem_p)?;

    let names_p = dir.join("tls.names");
    let want = names.join("\n");
    let have = std::fs::read_to_string(&names_p).unwrap_or_default();
    let tls_p = dir.join("tls.pem");
    let tls_key_p = dir.join("tls.key");
    if have != want || !tls_p.exists() || !tls_key_p.exists() {
        let leaf_kp = KeyPair::generate()?;
        let mut p = CertificateParams::new(names.to_vec())?;
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            names.first().cloned().unwrap_or_default(),
        );
        p.distinguished_name = dn;
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let year = 1970 + (now / 31_556_952) as i32;
        p.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
        p.not_after = rcgen::date_time_ymd(year + 2, 1, 1);
        let leaf = p.signed_by(&leaf_kp, &ca_cert, &ca_kp)?;
        let chain = format!("{}{}", leaf.pem(), ca_pem);
        write_atomic(&tls_p, chain.as_bytes(), false)?;
        write_private(&tls_key_p, leaf_kp.serialize_pem().as_bytes())?;
        write_atomic(&names_p, want.as_bytes(), false)?;
    }

    let sk_p = dir.join("signing.key");
    let signing_pkcs8 = if sk_p.exists() {
        STANDARD
            .decode(std::fs::read_to_string(&sk_p)?.trim())
            .context("signing.key invalida")?
    } else {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| anyhow!("falha ao gerar a chave de assinatura"))?;
        write_private(&sk_p, STANDARD.encode(doc.as_ref()).as_bytes())?;
        doc.as_ref().to_vec()
    };
    Ok(Pki {
        ca_pem,
        tls_chain_pem: std::fs::read_to_string(&tls_p)?,
        tls_key_pem: std::fs::read_to_string(&tls_key_p)?,
        signing_pkcs8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cria_e_reaproveita() {
        let d = tempfile::tempdir().unwrap();
        let names = vec!["127.0.0.1".to_string(), "central.test".to_string()];
        let a = ensure(d.path(), &names).unwrap();
        let b = ensure(d.path(), &names).unwrap();
        assert_eq!(a.ca_pem, b.ca_pem);
        assert_eq!(a.tls_chain_pem, b.tls_chain_pem);
        assert_eq!(a.signing_pkcs8, b.signing_pkcs8);
        let c = ensure(d.path(), &names[..1]).unwrap();
        assert_eq!(a.ca_pem, c.ca_pem);
        assert_ne!(a.tls_chain_pem, c.tls_chain_pem);
        openvnc_transport::tls::ServerIdentity::from_pem(
            c.tls_chain_pem.as_bytes(),
            c.tls_key_pem.as_bytes(),
        )
        .unwrap();
    }
}
