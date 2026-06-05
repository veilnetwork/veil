use std::{fs, path::Path};

use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer,
    pem::{Error as PemError, PemObject},
};

use super::error::{Result, TransportError};

fn absolute_display(path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

pub fn load_certificates_from_file(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path).map_err(|err| {
        TransportError::Io(std::io::Error::new(
            err.kind(),
            format!("{}: {}", absolute_display(path).display(), err),
        ))
    })?;
    if bytes.starts_with(b"-----BEGIN") {
        // followup: migrated от unmaintained `rustls-pemfile`
        // (RUSTSEC-2025-0134) к the native `PemObject` trait в
        // `rustls-pki-types ≥ 1.14`. Iterates only CERTIFICATE-kind
        // sections; other section kinds (private keys, etc.) ара
        // silently skipped by `pem_slice_iter`'s filter, which matches
        // the prior `rustls_pemfile::certs` behaviour.
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
            .collect::<std::result::Result<Vec<_>, PemError>>()
            .map_err(|err| TransportError::Tls(err.to_string()))?;
        if certs.is_empty() {
            return Err(TransportError::Tls(format!(
                "no PEM certificates found in {}",
                path.display()
            )));
        }
        Ok(certs)
    } else {
        Ok(vec![CertificateDer::from(bytes)])
    }
}

pub fn load_private_key_from_file(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = fs::read(path).map_err(|err| {
        TransportError::Io(std::io::Error::new(
            err.kind(),
            format!("{}: {}", absolute_display(path).display(), err),
        ))
    })?;
    if bytes.starts_with(b"-----BEGIN") {
        // followup: `PrivateKeyDer::from_pem_slice`
        // handles all three private-key kinds (PKCS#1 RSA, SEC1 EC
        // PKCS#8) в а single pass thanks к the type's `PemObject` impl
        // (see rustls-pki-types/src/lib.rs:171). Replaces the
        // unmaintained `rustls-pemfile` 3-pass scan (pkcs8 → ec → rsa)
        // closing RUSTSEC-2025-0134.
        PrivateKeyDer::from_pem_slice(&bytes).map_err(|err| {
            TransportError::Tls(format!(
                "no supported PEM private key found in {}: {err}",
                path.display()
            ))
        })
    } else {
        Ok(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(bytes)))
    }
}

pub fn explain_tls_error(message: impl Into<String>) -> String {
    let message = message.into();
    if message.contains("CaUsedAsEndEntity") {
        return format!(
            "{message}; the peer presented a CA certificate as a server certificate, use a leaf/fullchain certificate for `--tls-cert` and a CA/root certificate for `--tls-ca-cert`"
        );
    }
    if message.contains("CertificateUnknown") {
        return format!(
            "{message}; the remote peer rejected the certificate, check that the listener uses a leaf/fullchain server certificate and the client trusts the issuing CA via `--tls-ca-cert`"
        );
    }
    message
}
