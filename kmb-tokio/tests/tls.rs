#![cfg(feature = "tls")]

use kmb_tokio::tls::{self, Trust, Verifier};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};

struct Chain {
    root_x: [u8; 32],
    root_y: [u8; 32],
    leaf: CertificateDer<'static>,
    intermediate: CertificateDer<'static>,
}

#[cfg(test)]
fn ca(name: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p
}

#[cfg(test)]
fn chain() -> Chain {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let root_params = ca("Test Root CA");
    let root = Issuer::from_params(&root_params, &root_key);
    let mid_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mid_params = ca("Intermediate CA");
    let intermediate = mid_params.signed_by(&mid_key, &root).unwrap();
    let mid = Issuer::from_params(&mid_params, &mid_key);
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "default (factory default)");
    let leaf = leaf_params.signed_by(&leaf_key, &mid).unwrap();
    let point = root_key.public_key_raw();
    assert_eq!((point.len(), point[0]), (65, 4));
    Chain {
        root_x: point[1..33].try_into().unwrap(),
        root_y: point[33..].try_into().unwrap(),
        leaf: leaf.der().clone(),
        intermediate: intermediate.der().clone(),
    }
}

#[cfg(test)]
fn check(trust: Trust, c: &Chain) -> bool {
    let name = ServerName::try_from(tls::SERVER_NAME).unwrap();
    Verifier::new(trust)
        .verify_server_cert(
            &c.leaf,
            std::slice::from_ref(&c.intermediate),
            &name,
            &[],
            UnixTime::now(),
        )
        .is_ok()
}

#[test]
fn chain_to_root() {
    let c = chain();
    assert!(check(Trust::Root(c.root_x, c.root_y), &c));
    let other = chain();
    assert!(!check(Trust::Root(other.root_x, other.root_y), &c));
}

#[test]
fn pinned() {
    let c = chain();
    let other = chain();
    let pin = tls::fingerprint(&c.leaf);
    assert!(check(Trust::Pinned(vec![pin]), &c));
    assert!(!check(Trust::Pinned(vec![[0; 32]]), &c));
    assert!(check(
        Trust::RootOrPinned(other.root_x, other.root_y, vec![pin]),
        &c
    ));
    assert!(!check(
        Trust::RootOrPinned(other.root_x, other.root_y, vec![[0; 32]]),
        &c
    ));
}

#[test]
fn issuer_name() {
    let c = chain();
    let issuer = tls::issuer(&c.intermediate).unwrap();
    assert!(issuer.windows(12).any(|w| w == b"Test Root CA"));
    assert!(tls::issuer(&[0x30, 0x03, 0x02, 0x01]).is_none());
}

#[test]
fn issuer_malformed() {
    // the walker must reject or return a slice, never panic, on any truncation or bit flip
    let der = chain().intermediate.to_vec();
    for len in 0..der.len() {
        let _ = tls::issuer(&der[..len]);
    }
    for i in 0..der.len() {
        for bit in 0..8 {
            let mut bad = der.clone();
            bad[i] ^= 1 << bit;
            let _ = tls::issuer(&bad);
        }
    }
}

#[test]
fn spki() {
    let spki = tls::p256_spki(&[0x11; 32], &[0x22; 32]);
    assert_eq!(spki.len(), 25 + 64);
    assert_eq!(spki[24..26], [0x04, 0x11]);
    assert_eq!(spki[spki.len() - 1], 0x22);
}

#[test]
fn root_point_from_hex() {
    use std::fmt::Write;
    let c = chain();
    let xy = c
        .root_x
        .iter()
        .chain(&c.root_y)
        .fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        });
    assert_eq!(
        tls::parse_p256_point(&format!("04{xy}")),
        Some((c.root_x, c.root_y))
    );
    assert_eq!(tls::parse_p256_point(&format!("05{xy}")), None);
    assert_eq!(tls::parse_p256_point(&xy), None);
    assert_eq!(tls::parse_hex::<2>("AB:cd"), Some([0xAB, 0xCD]));
    assert_eq!(tls::parse_hex::<2>("ABzz"), None);
}
