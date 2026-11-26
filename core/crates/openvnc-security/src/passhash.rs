//! Hash de senhas com Argon2id (formato PHC). A configuracao guarda so o
//! hash; a senha nunca e gravada em disco.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};

/// Gera o hash PHC (`$argon2id$...`) de `password`.
pub fn hash(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Confere `password` contra um hash PHC. Hash invalido nunca confere.
pub fn verify(password: &[u8], phc: &str) -> bool {
    PasswordHash::new(phc)
        .map(|h| Argon2::default().verify_password(password, &h).is_ok())
        .unwrap_or(false)
}

/// Forca estimada de 0 (fraca) a 4 (forte), por tamanho e variedade.
pub fn strength(password: &str) -> u8 {
    let n = password.chars().count();
    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    match (n, classes) {
        (0..=7, _) => 0,
        (8..=11, 0..=2) => 1,
        (8..=11, _) | (12..=15, 0..=2) => 2,
        (12..=15, _) | (16..=19, _) => 3,
        _ => 4,
    }
}

/// Senha aleatoria forte (20 caracteres sem ambiguos).
pub fn generate() -> String {
    use rand::Rng;
    const A: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#";
    let mut r = rand::thread_rng();
    (0..20)
        .map(|_| A[r.gen_range(0..A.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = hash("segredo-forte").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify(b"segredo-forte", &h));
        assert!(!verify(b"outra", &h));
        assert!(!verify(b"x", "lixo"));
    }

    #[test]
    fn forca() {
        assert_eq!(strength("abc"), 0);
        assert!(strength(&generate()) >= 4);
    }
}
