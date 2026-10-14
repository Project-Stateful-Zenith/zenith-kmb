use crate::{CONNECT_TIMEOUT, Client, Error, Result, SETTLE};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    CryptoProvider, ring, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

pub const SERVER_NAME: &str = "default";

#[must_use]
pub fn p256_spki(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    out
}

fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        let mut be = [0; 4];
        be.get_mut(4_usize.checked_sub(n)?..)?
            .copy_from_slice(bytes);
        (usize::try_from(u32::from_be_bytes(be)).ok()?, rest)
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

#[must_use]
pub fn issuer(cert: &[u8]) -> Option<&[u8]> {
    let (0x30, cert, _) = der(cert)? else {
        return None;
    };
    let (0x30, tbs, _) = der(cert)? else {
        return None;
    };
    let (tag, _, rest) = der(tbs)?;
    let rest = if tag == 0xA0 { der(rest)?.2 } else { rest };
    let (_signature, _, rest) = der(rest)?;
    let (0x30, name, _) = der(rest)? else {
        return None;
    };
    Some(name)
}

#[must_use]
pub fn fingerprint(cert: &[u8]) -> [u8; 32] {
    Sha256::digest(cert).into()
}

#[must_use]
pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let digits: Vec<u8> = s.bytes().filter(|c| !matches!(c, b':' | b' ')).collect();
    if digits.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0; N];
    for (b, pair) in out.iter_mut().zip(digits.chunks(2)) {
        *b = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

#[must_use]
pub fn parse_p256_point(s: &str) -> Option<([u8; 32], [u8; 32])> {
    let point: [u8; 65] = parse_hex(s)?;
    let (&tag, xy) = point.split_first()?;
    if tag != 4 {
        return None;
    }
    let (x, y) = xy.split_at_checked(32)?;
    Some((x.try_into().ok()?, y.try_into().ok()?))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trust {
    Root([u8; 32], [u8; 32]),
    Pinned(Vec<[u8; 32]>),
    RootOrPinned([u8; 32], [u8; 32], Vec<[u8; 32]>),
}

#[derive(Debug)]
pub struct Verifier {
    trust: Trust,
    provider: Arc<CryptoProvider>,
}

fn tls_error(e: impl std::fmt::Display) -> tokio_rustls::rustls::Error {
    tokio_rustls::rustls::Error::General(e.to_string())
}

impl Verifier {
    #[must_use]
    pub fn new(trust: Trust) -> Self {
        Self {
            trust,
            provider: Arc::new(ring::default_provider()),
        }
    }

    fn chain(
        root: (&[u8; 32], &[u8; 32]),
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<(), tokio_rustls::rustls::Error> {
        let top = intermediates.last().unwrap_or(end_entity);
        let subject = issuer(top).ok_or_else(|| tls_error("certificate is not DER"))?;
        let spki = p256_spki(root.0, root.1);
        let anchor = TrustAnchor {
            subject: subject.into(),
            subject_public_key_info: spki.as_slice().into(),
            name_constraints: None,
        };
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(tls_error)?;
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
        .map_err(tls_error)
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let pins = match &self.trust {
            Trust::Root(..) => &[][..],
            Trust::Pinned(p) | Trust::RootOrPinned(_, _, p) => p,
        };
        if pins.contains(&fingerprint(end_entity)) {
            return Ok(ServerCertVerified::assertion());
        }
        let root = match &self.trust {
            Trust::Pinned(_) => return Err(tls_error("certificate is not pinned")),
            Trust::Root(x, y) | Trust::RootOrPinned(x, y, _) => (x, y),
        };
        Self::chain(root, end_entity, intermediates, now).map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn try_client_config(
    trust: Trust,
) -> std::result::Result<ClientConfig, tokio_rustls::rustls::Error> {
    let provider = Arc::new(ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier { trust, provider }))
        .with_no_client_auth())
}

#[must_use]
#[allow(
    clippy::expect_used,
    reason = "the ring provider always supports the default protocol versions; \
              connect_tls uses the fallible form"
)]
pub fn client_config(trust: Trust) -> ClientConfig {
    try_client_config(trust).expect("the ring provider supports the default versions")
}

pub async fn connect_tls(
    addr: impl ToSocketAddrs,
    address: u8,
    trust: Trust,
) -> Result<Client<TlsStream<TcpStream>>> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout)??;
    tcp.set_nodelay(true)?;
    let config = try_client_config(trust).map_err(std::io::Error::other)?;
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(SERVER_NAME).map_err(std::io::Error::other)?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| Error::Timeout)??;
    tokio::time::sleep(SETTLE).await;
    let mut client = Client::new(stream, address);
    client.set_one_frame_archives(true);
    Ok(client)
}
