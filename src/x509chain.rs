// SPDX-License-Identifier: MIT

//! X.509 chain validation for CoRIM [`SignedCorim`] x5chain verification.
//!
//! This module implements PKIX path validation (RFC 5280 core checks), optional
//! strict CRL revocation checking when CRL material is supplied (CRL_CHECK_ALL-equivalent
//! for non-anchor certificates on the verified chain; applied post-PKIX because the
//! `openssl` crate does not bind `X509_STORE_add_crl`), and COSE signature verification
//! using the validated leaf certificate public key.
//!
//! Load trust material with [`load_trust_anchors`]. When `trust_anchor_paths` is
//! empty, the operating-system trust store is consulted at verify time — it is
//! reloaded on every verify call and is not cached, so OS trust-store changes take
//! effect on the next call. When paths are supplied, only those anchors are trusted
//! (explicit override; no merge with system trust anchors).
//!
//! **CRL policy:** no CRL paths → skip revocation; non-empty CRL list → post-PKIX
//! checks governed by [`CrlPolicy`] (default [`CrlPolicy::Strict`], OpenSSL
//! `CRL_CHECK_ALL`-equivalent for non-anchor certificates). Name-matching CRLs
//! with invalid signatures fail verification (not treated as “no matching CRL”).
//!
//! For verification with an external JWK or PEM key (no PKIX), use
//! [`SignedCorim::verify_signature`] in the `corim` module instead.
//!
//! ## Primary API
//!
//! - [`load_trust_anchors`]
//! - [`SignedCorim::verify_with_x5chain`]
//!
//! ## Advanced API
//!
//! - [`verify_with_x5chain`] (free function) — PKIX + CRL on a DER chain; **no COSE verify**
//! - [`verify_x509_chain`] — structural parent/child signatures only (no PKIX trust)
//! - [`TrustAnchors::from_der_anchors_and_crls`], [`parse_certificate_der_or_pem`]
//!
//! ## Notes
//!
//! - **PKIX path selection:** OpenSSL `verify_cert` returns one verified chain per call;
//!   this module uses that result directly.
//! - **CRL when `crls` is non-empty:** default [`CrlPolicy::Strict`] requires every
//!   non-anchor issuer on the verified chain to have a valid matching CRL; each matching
//!   CRL must include `nextUpdate`. [`CrlPolicy::Permissive`] skips issuers with no
//!   matching CRL. A CRL whose issuer name matches but signature verification fails is
//!   always fatal (not treated as “no matching CRL”). Empty `crls` → no revocation
//!   check in both cases.
//! - **CRL features:** only base (full) CRLs are supported. Delta CRLs, indirect CRLs,
//!   and CRL distribution-point fetching are not handled — each supplied CRL is checked
//!   independently for revoked serials. Supply full CRLs covering every non-anchor
//!   issuer when revocation must be enforced.
//! - **Signing key types:** COSE verification only supports EC2 keys (P-256/P-384/P-521)
//!   via [`OpensslSigner`] (ES256/ES384/ES512). RSA, EdDSA, and other leaf certificate
//!   key types are rejected with [`X5chainError::UnsupportedKeyType`].
//! - **Pinned intermediate anchors:** OpenSSL `PARTIAL_CHAIN` allows a presented
//!   intermediate CA to serve as a trust anchor.
//! - **x5chain size limits:** each COSE element and parsed certificate is capped at
//!   256 KiB DER; intermediate COSE elements are limited in count and total concatenated
//!   size before parsing.

use crate::core::{Bytes, OneOrMore};
use crate::corim::SignedCorim;
use crate::openssl::{
    certificate_der_from_pem_or_der, certificate_from_der, certificate_from_pem_or_der,
    crl_from_der, crl_signed_by_issuer, for_each_pem_block, parse_concatenated_certificate_ders,
    validate_signing_certificate, AnchorLoader, OpensslSigner,
};
use crate::{CorimError, X5chainCrlLoadErrorKind, X5chainError};
use openssl::asn1::Asn1Time;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{
    CrlStatus, X509Crl, X509CrlRef, X509PurposeId, X509Ref, X509VerifyResult, X509,
};
use openssl_sys as ffi;
use rustls_native_certs::load_native_certs;
use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum DER size for a single x5chain certificate (signing cert or one intermediate TLV).
const X5CHAIN_MAX_CERT_DER_BYTES: usize = 256 * 1024;

/// Maximum COSE x5chain array elements after the signing certificate.
const X5CHAIN_MAX_INTERMEDIATE_COSE_ELEMENTS: usize = 16;

/// Maximum total bytes concatenated from intermediate COSE elements before parsing.
const X5CHAIN_MAX_INTERMEDIATE_TOTAL_BYTES: usize = 256 * 1024;

/// Maximum certificates in a flattened x5chain (signing + intermediates).
const X5CHAIN_MAX_CHAIN_CERTS: usize = 16;

/// How missing issuer CRLs are handled when `TrustAnchors::crls` is non-empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CrlPolicy {
    /// Every in-chain issuer on the verified chain must have a valid matching CRL
    /// (CRL_CHECK_ALL-equivalent for non-anchor certificates; the trust anchor at
    /// the chain end is not checked). Each matching CRL must include `nextUpdate`.
    /// A CRL whose issuer name matches but signature is invalid is always fatal.
    /// This is the default.
    #[default]
    Strict,
    /// Skip revocation for in-chain issuers with no matching CRL. When matching CRLs
    /// exist but are all invalid, verification still fails. A CRL whose issuer name
    /// matches but signature is invalid is always fatal.
    Permissive,
}

/// Trust anchors and optional CRLs for x5chain validation.
///
/// `anchors == None` loads system anchors at verify time on each verify call.
/// `anchors == Some(vec)` uses only explicit anchors; an empty vector is explicit-trust-only.
///
/// **System trust backend:** uses [`rustls-native-certs`] (platform PEM bundles).
/// The store is reloaded on every verify call and is not cached. When the OS trust store is used, certificates that cannot be parsed as X.509 are
/// **skipped** (they do not fail verification unless no usable anchors remain).
/// `rustls-native-certs` load errors are included in the error when the resulting anchor set
/// is empty.
///
/// `crls` empty → skip revocation. `crls` non-empty → post-PKIX checks per [`CrlPolicy`]
/// (default [`CrlPolicy::Strict`]). Prefer building via [`load_trust_anchors`].
pub struct TrustAnchors {
    pub(crate) anchors: Option<Vec<X509>>,
    pub(crate) crls: Vec<X509Crl>,
    pub(crate) crl_policy: CrlPolicy,
    pub(crate) current_time: Option<i64>,
}

impl TrustAnchors {
    /// Override validation time (Unix seconds). Used mainly in tests.
    pub fn with_validation_time(mut self, unix_secs: i64) -> Self {
        self.current_time = Some(unix_secs);
        self
    }

    /// Override CRL policy when `crls` is non-empty. Default is [`CrlPolicy::Strict`].
    pub fn with_crl_policy(mut self, policy: CrlPolicy) -> Self {
        self.crl_policy = policy;
        self
    }

    /// Build trust anchors from in-memory DER-encoded certificates and CRLs.
    ///
    /// Parsed anchors are stored as explicit trust (`anchors == Some(...)`); an empty
    /// `anchor_ders` slice yields explicit-trust-only (no system roots), matching
    /// `load_trust_anchors` with non-empty paths that load zero certificates.
    /// Non-empty `crl_ders` enables post-PKIX revocation per [`CrlPolicy`] (see [`TrustAnchors`]).
    pub fn from_der_anchors_and_crls(
        anchor_ders: Vec<Vec<u8>>,
        crl_ders: Vec<Vec<u8>>,
    ) -> Result<Self, CorimError> {
        let anchors = anchor_ders
            .into_iter()
            .map(|der| {
                certificate_from_der(&der).map_err(|e| {
                    CorimError::custom(format!("parsing trust anchor certificate: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let crls = crl_ders
            .into_iter()
            .map(|der| crl_from_der(&der))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            anchors: Some(anchors),
            crls,
            crl_policy: CrlPolicy::default(),
            current_time: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_anchors(anchors: Vec<X509>) -> Self {
        Self {
            anchors: Some(anchors),
            crls: Vec::new(),
            crl_policy: CrlPolicy::default(),
            current_time: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_anchors_and_crls(anchors: Vec<X509>, crls: Vec<X509Crl>) -> Self {
        Self {
            anchors: Some(anchors),
            crls,
            crl_policy: CrlPolicy::default(),
            current_time: None,
        }
    }
}

fn crls_from_der_or_pem(data: &[u8]) -> Result<Vec<X509Crl>, X5chainCrlLoadErrorKind> {
    let data = data.trim_ascii_start();
    if !data.starts_with(b"-----BEGIN") {
        let crl = crl_from_der(data).map_err(|e| X5chainCrlLoadErrorKind::Parse(e.to_string()))?;
        return Ok(vec![crl]);
    }

    let mut crls = Vec::new();
    for_each_pem_block(data, |label, contents| {
        if label != "X509 CRL" {
            return Err(CorimError::X5chain(X5chainError::CrlLoadError {
                path: String::new(),
                kind: X5chainCrlLoadErrorKind::InvalidPemBlockType(label.to_string()),
            }));
        }
        let crl = crl_from_der(contents)?;
        crls.push(crl);
        Ok(())
    })
    .map_err(|e| match e {
        CorimError::X5chain(X5chainError::CrlLoadError { kind, .. }) => kind,
        other => X5chainCrlLoadErrorKind::Parse(other.to_string()),
    })?;

    if crls.is_empty() {
        return Err(X5chainCrlLoadErrorKind::NoCrlPemBlock);
    }

    Ok(crls)
}

fn append_trust_anchors_from_der_or_pem(
    loader: &mut AnchorLoader,
    data: &[u8],
) -> Result<(), CorimError> {
    let data = data.trim_ascii_start();
    if data.starts_with(b"-----BEGIN") {
        let mut loaded = false;
        for_each_pem_block(data, |label, contents| {
            if label != "CERTIFICATE" {
                return Ok(());
            }
            loaded = true;
            loader.push_deduped(certificate_from_der(contents)?)?;
            Ok(())
        })?;
        if loaded {
            return Ok(());
        }
    }

    loader.push_deduped(certificate_from_pem_or_der(data)?)?;
    Ok(())
}

/// Load trust anchors and CRLs from files into a [`TrustAnchors`] value.
///
/// When `trust_anchor_paths` is empty, `anchors` is `None` and verification uses the OS
/// trust store. When non-empty, only those anchors are trusted (override; no system merge).
///
/// System-store loading skips certificates that fail to parse; verification fails only when
/// no trusted anchors remain after loading (see [`TrustAnchors`]).
///
/// When `crl_paths` is empty, no revocation checks run. When non-empty, loaded CRLs
/// enable post-PKIX checks per [`CrlPolicy`] (default [`CrlPolicy::Strict`]; see
/// [`TrustAnchors`]).
///
/// Each anchor or CRL path may be DER or PEM. PEM anchor files may contain multiple
/// `CERTIFICATE` blocks; PEM CRL files may contain multiple `X509 CRL` blocks; DER
/// files hold a single object. Multi-block PEM is walked with [`x509_parser`]; each
/// certificate or CRL DER is validated with OpenSSL `d2i_*` (exact length, no trailing
/// bytes). Duplicate anchor DER values are deduplicated when loading.
pub fn load_trust_anchors<F>(
    read_file: F,
    trust_anchor_paths: &[impl AsRef<str>],
    crl_paths: &[impl AsRef<str>],
) -> Result<TrustAnchors, CorimError>
where
    F: Fn(&str) -> Result<Vec<u8>, CorimError>,
{
    let anchors = if trust_anchor_paths.is_empty() {
        None
    } else {
        let mut loader = AnchorLoader::new();
        for path in trust_anchor_paths {
            let path = path.as_ref();
            let data = read_file(path).map_err(|e| {
                CorimError::custom(format!("loading trust anchor from {path}: {e}"))
            })?;
            append_trust_anchors_from_der_or_pem(&mut loader, &data).map_err(|e| {
                CorimError::custom(format!("parsing trust anchor from {path}: {e}"))
            })?;
        }
        Some(loader.into_certs())
    };

    let mut crls = Vec::new();
    for path in crl_paths {
        let path = path.as_ref();
        let data = read_file(path)
            .map_err(|e| CorimError::custom(format!("loading CRL from {path}: {e}")))?;
        let loaded = crls_from_der_or_pem(&data).map_err(|kind| {
            CorimError::X5chain(X5chainError::CrlLoadError {
                path: path.to_string(),
                kind,
            })
        })?;
        crls.extend(loaded);
    }

    Ok(TrustAnchors {
        anchors,
        crls,
        crl_policy: CrlPolicy::default(),
        current_time: None,
    })
}

fn load_system_trust_anchors() -> Result<Vec<X509>, CorimError> {
    let native = load_native_certs();

    let mut loader = AnchorLoader::new();
    let mut skipped = 0usize;
    for cert in native.certs {
        match certificate_from_der(cert.as_ref()) {
            Ok(parsed) => loader.push_deduped(parsed)?,
            Err(_) => skipped += 1,
        }
    }

    let trust_anchors = loader.into_certs();
    if trust_anchors.is_empty() {
        let errors = if native.errors.is_empty() {
            String::new()
        } else {
            let msgs: Vec<String> = native.errors.iter().map(|e| e.to_string()).collect();
            format!(" ({})", msgs.join("; "))
        };
        let message = if skipped > 0 {
            format!(
                "loading system cert pool: no trusted anchors loaded ({skipped} certificate(s) could not be parsed){errors}"
            )
        } else {
            format!("loading system cert pool: no trusted anchors configured{errors}")
        };
        return Err(CorimError::custom(message));
    }

    Ok(trust_anchors)
}

fn verify_cert_signed_by(cert: &X509Ref, issuer: &X509Ref) -> Result<(), CorimError> {
    let key = issuer.public_key().map_err(|e| {
        CorimError::X5chain(X5chainError::InvalidCertificateSignature(e.to_string()))
    })?;
    if !cert.verify(&key).map_err(|e| {
        CorimError::X5chain(X5chainError::InvalidCertificateSignature(e.to_string()))
    })? {
        return Err(CorimError::X5chain(
            X5chainError::InvalidCertificateSignature("certificate signature invalid".into()),
        ));
    }
    Ok(())
}

/// Parse a single X.509 certificate from DER or PEM (`CERTIFICATE` block).
///
/// Returns canonical DER bytes (OpenSSL re-encoded). Rejects trailing bytes after one
/// DER object. PEM uses [`x509_parser`] for the first block label; DER validation
/// uses OpenSSL `d2i_X509` (see [`crate::openssl::certificate_from_der`]).
pub fn parse_certificate_der_or_pem(data: &[u8]) -> Result<Vec<u8>, CorimError> {
    certificate_der_from_pem_or_der(data)
}

/// Structural chain check for x5chain assembly: each certificate must be signed by the next.
///
/// **Not PKIX trust validation** — no trust anchors, CRL, or leaf signing policy.
/// For PKIX + CRL use the free function [`verify_with_x5chain`]; for a full signed CoRIM
/// use [`SignedCorim::verify_with_x5chain`].
pub fn verify_x509_chain(chain_ders: &[impl AsRef<[u8]>]) -> Result<(), CorimError> {
    verify_certificate_chain_signed_by(chain_ders)
}

/// Structural chain check: each cert must be signed by the next (no PKIX trust).
fn verify_certificate_chain_signed_by(chain_ders: &[impl AsRef<[u8]>]) -> Result<(), CorimError> {
    match chain_ders.len() {
        0 => Err(CorimError::X5chain(X5chainError::EmptyChain)),
        1 => Ok(()),
        _ => {
            let certs: Vec<X509> = chain_ders
                .iter()
                .map(|der| certificate_from_der(der.as_ref()))
                .collect::<Result<Vec<_>, _>>()?;
            for i in 0..certs.len() - 1 {
                verify_cert_signed_by(&certs[i], &certs[i + 1])?;
            }
            Ok(())
        }
    }
}

fn validation_time(anchors: &TrustAnchors) -> Result<i64, CorimError> {
    match anchors.current_time {
        Some(secs) => Ok(secs),
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CorimError::custom(format!("system time before Unix epoch: {e}")))
            .and_then(|duration| {
                i64::try_from(duration.as_secs())
                    .map_err(|_| CorimError::custom("system time exceeds i64 seconds range"))
            }),
    }
}

fn intermediates_from_chain(chain: &[X509]) -> Result<Stack<X509>, CorimError> {
    let mut stack = Stack::new().map_err(CorimError::custom)?;

    for cert in chain.iter().skip(1) {
        stack.push(cert.clone()).map_err(CorimError::custom)?;
    }

    Ok(stack)
}

enum PkixFailure {
    /// OpenSSL returned a structured verification error code.
    VerifyError(X509VerifyResult),
    /// A pre/post-check failed without an OpenSSL error code.
    Other(String),
}

/// PKIX path validation against the given trust anchors.
///
/// Returns `Ok(Err(PkixFailure))` for expected verification failures; the caller maps those
/// via [`pkix_failure_error`]. Outer `Err` is for OpenSSL store/context setup failures.
fn verify_pkix_with_trust_anchors(
    chain: &[X509],
    trust_anchors: &[X509],
    now_secs: i64,
) -> Result<Result<Vec<X509>, PkixFailure>, CorimError> {
    if trust_anchors.is_empty() {
        return Ok(Err(PkixFailure::Other(
            "no trusted anchors configured".into(),
        )));
    }

    let mut store_builder = X509StoreBuilder::new().map_err(CorimError::custom)?;
    for trust_anchor in trust_anchors {
        store_builder
            .add_cert(trust_anchor.clone())
            .map_err(CorimError::custom)?;
    }

    let mut verify_params = X509VerifyParam::new().map_err(CorimError::custom)?;
    verify_params.set_time(now_secs);
    // ANY skips EKU/purpose enforcement during PKIX path validation. Leaf signing-key
    // policy is enforced separately by `validate_signing_certificate` before PKIX.
    verify_params
        .set_purpose(X509PurposeId::ANY)
        .map_err(CorimError::custom)?;
    // Allow explicit trust anchors that are not self-signed roots (e.g. pinned issuing CA).
    verify_params
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(CorimError::custom)?;
    store_builder
        .set_param(&verify_params)
        .map_err(CorimError::custom)?;

    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new().map_err(CorimError::custom)?;
    let intermediates = intermediates_from_chain(chain)?;
    let leaf = &chain[0];

    let mut verified_chain: Vec<X509> = Vec::new();
    let mut failure: Option<PkixFailure> = None;

    ctx.init(&store, leaf, &intermediates, |ctx| {
        match ctx.verify_cert() {
            Ok(true) => {
                if let Some(chain) = ctx.chain() {
                    verified_chain = chain.iter().map(X509Ref::to_owned).collect();
                }
                Ok(())
            }
            Ok(false) => {
                failure = Some(PkixFailure::VerifyError(ctx.error()));
                Ok(())
            }
            Err(err) => Err(err),
        }
    })
    .map_err(|e| CorimError::X5chain(X5chainError::VerificationFailed(e.to_string())))?;

    if let Some(failure) = failure {
        return Ok(Err(failure));
    }
    if verified_chain.is_empty() {
        return Ok(Err(PkixFailure::Other("no verified chain".into())));
    }
    Ok(Ok(verified_chain))
}

/// Map a PKIX failure to an [`X5chainError`]. Revocation and CRL validity errors are
/// returned from post-PKIX [`check_chain_revocation`], not from OpenSSL PKIX.
fn pkix_failure_error(failure: &PkixFailure) -> X5chainError {
    match failure {
        PkixFailure::VerifyError(result) => match result.as_raw() {
            ffi::X509_V_ERR_CERT_HAS_EXPIRED => X5chainError::CertificateExpired,
            ffi::X509_V_ERR_CERT_NOT_YET_VALID => X5chainError::CertificateNotYetValid,
            _ => X5chainError::VerificationFailed(result.error_string().to_string()),
        },
        PkixFailure::Other(message) => X5chainError::VerificationFailed(message.clone()),
    }
}

fn verify_pkix_chain(
    chain: &[X509],
    anchors: &TrustAnchors,
    now_secs: i64,
) -> Result<Vec<X509>, CorimError> {
    let result = match &anchors.anchors {
        None => {
            let system_trust_anchors = load_system_trust_anchors().map_err(|e| {
                CorimError::X5chain(X5chainError::VerificationFailed(e.to_string()))
            })?;
            verify_pkix_with_trust_anchors(chain, &system_trust_anchors, now_secs)?
        }
        Some(explicit) => verify_pkix_with_trust_anchors(chain, explicit, now_secs)?,
    };

    match result {
        Ok(verified_chain) => Ok(verified_chain),
        Err(failure) => Err(CorimError::X5chain(pkix_failure_error(&failure))),
    }
}

fn asn1_time_from_unix(now_secs: i64) -> Result<Asn1Time, CorimError> {
    Asn1Time::from_unix(now_secs).map_err(|e| CorimError::custom(format!("validation time: {e}")))
}

fn filter_crls_for_issuer<'a>(
    issuer: &X509Ref,
    crls: &'a [X509Crl],
) -> Result<Vec<&'a X509CrlRef>, CorimError> {
    // Only CRLs signed by `issuer` are candidates; unrelated CRLs in `crls` are ignored.
    // Name-matching CRLs with invalid signatures fail here (not treated as non-matching).
    let mut issuer_crls = Vec::new();
    for crl in crls {
        if crl_signed_by_issuer(crl, issuer)? {
            issuer_crls.push(crl as &X509CrlRef);
        }
    }
    Ok(issuer_crls)
}

fn check_crl_validity(
    crl: &X509CrlRef,
    policy: CrlPolicy,
    now_secs: i64,
) -> Result<(), CorimError> {
    let now = asn1_time_from_unix(now_secs)?;

    match now.compare(crl.last_update()) {
        Ok(Ordering::Less) => return Err(CorimError::X5chain(X5chainError::CrlNotYetValid)),
        Err(e) => {
            return Err(CorimError::custom(format!("comparing CRL lastUpdate: {e}")));
        }
        Ok(_) => {}
    }

    match crl.next_update() {
        Some(next_update) => match now.compare(next_update) {
            Ok(Ordering::Greater) => return Err(CorimError::X5chain(X5chainError::CrlExpired)),
            Err(e) => return Err(CorimError::custom(format!("comparing CRL nextUpdate: {e}"))),
            Ok(_) => {}
        },
        None if policy == CrlPolicy::Strict => {
            return Err(CorimError::X5chain(X5chainError::CrlMissingNextUpdate));
        }
        None => {}
    }

    Ok(())
}

fn is_serial_revoked(cert: &X509Ref, crl: &X509CrlRef) -> bool {
    matches!(
        crl.get_by_serial(cert.serial_number()),
        CrlStatus::Revoked(_)
    )
}

/// Post-PKIX CRL check when `crls` is non-empty.
///
/// For each `(certificate, issuer)` pair in the verified chain (excluding the trust
/// anchor at the chain end), [`CrlPolicy::Strict`] requires at least one **valid** CRL
/// in `crls` signed by `issuer`. [`CrlPolicy::Permissive`] skips issuers with no matching
/// CRL. Name-matching CRLs with invalid signatures fail during filtering (not skipped).
/// Missing issuer CRL under strict policy → `unable to get certificate CRL`.
/// Revoked serial → [`X5chainError::CertificateRevoked`]. Empty `crls` → no-op.
fn check_chain_revocation(
    chain: &[X509],
    crls: &[X509Crl],
    policy: CrlPolicy,
    now_secs: i64,
) -> Result<(), CorimError> {
    if crls.is_empty() {
        return Ok(());
    }

    for i in 0..chain.len().saturating_sub(1) {
        let cert = &chain[i];
        let issuer = &chain[i + 1];
        let issuer_crls = filter_crls_for_issuer(issuer, crls)?;
        if issuer_crls.is_empty() {
            if policy == CrlPolicy::Permissive {
                continue;
            }

            return Err(CorimError::X5chain(X5chainError::VerificationFailed(
                "unable to get certificate CRL".into(),
            )));
        }

        let mut validity_err: Option<CorimError> = None;
        let mut valid_crl_found = false;

        for crl in issuer_crls {
            match check_crl_validity(crl, policy, now_secs) {
                Err(err) => {
                    validity_err = Some(err);
                    continue;
                }
                Ok(()) => {
                    valid_crl_found = true;
                    if is_serial_revoked(cert, crl) {
                        return Err(CorimError::X5chain(X5chainError::CertificateRevoked));
                    }
                }
            }
        }

        if !valid_crl_found {
            return Err(validity_err.unwrap_or_else(|| {
                CorimError::X5chain(X5chainError::VerificationFailed(
                    "no valid CRL for certificate issuer".into(),
                ))
            }));
        }
    }

    Ok(())
}

/// Flatten a COSE x5chain to ordered DER certificates.
///
/// Array element `[0]` is the signing certificate. Elements `[1..]` are concatenated
/// and parsed as one or more intermediate certificates.
fn x5chain_flat_certificate_ders(x5chain: &OneOrMore<Bytes>) -> Result<Vec<Vec<u8>>, CorimError> {
    let mut iter = x5chain.iter();
    let signing_der = iter
        .next()
        .ok_or_else(|| CorimError::custom("decoding x5chain: empty x5chain array"))?;

    if signing_der.len() > X5CHAIN_MAX_CERT_DER_BYTES {
        return Err(CorimError::custom(format!(
            "decoding x5chain: signing certificate exceeds {X5CHAIN_MAX_CERT_DER_BYTES} byte limit"
        )));
    }

    certificate_from_der(signing_der.as_ref()).map_err(|e| {
        CorimError::custom(format!(
            "decoding x5chain: invalid signing certificate: {e}"
        ))
    })?;

    let mut ders = vec![signing_der.to_vec()];

    let mut intermediate_buf = Vec::new();
    let mut intermediate_elem_count = 0usize;
    for elem in iter {
        intermediate_elem_count += 1;
        if intermediate_elem_count > X5CHAIN_MAX_INTERMEDIATE_COSE_ELEMENTS {
            return Err(CorimError::custom(format!(
                "decoding x5chain: intermediate COSE elements exceed {X5CHAIN_MAX_INTERMEDIATE_COSE_ELEMENTS} limit"
            )));
        }
        if elem.len() > X5CHAIN_MAX_CERT_DER_BYTES {
            return Err(CorimError::custom(format!(
                "decoding x5chain: intermediate COSE element exceeds {X5CHAIN_MAX_CERT_DER_BYTES} byte limit"
            )));
        }
        let new_len = intermediate_buf
            .len()
            .checked_add(elem.len())
            .ok_or_else(|| {
                CorimError::custom("decoding x5chain: intermediate certificate data too large")
            })?;
        if new_len > X5CHAIN_MAX_INTERMEDIATE_TOTAL_BYTES {
            return Err(CorimError::custom(format!(
                "decoding x5chain: intermediate certificate data exceeds {X5CHAIN_MAX_INTERMEDIATE_TOTAL_BYTES} byte limit"
            )));
        }
        intermediate_buf.try_reserve(elem.len()).map_err(|e| {
            CorimError::custom(format!(
                "decoding x5chain: intermediate certificate data too large: {e}"
            ))
        })?;
        intermediate_buf.extend_from_slice(elem);
    }

    if !intermediate_buf.is_empty() {
        let intermediates = parse_concatenated_certificate_ders(&intermediate_buf)?;
        ders.extend(intermediates);
    }

    if ders.len() > X5CHAIN_MAX_CHAIN_CERTS {
        return Err(CorimError::custom(format!(
            "decoding x5chain: certificate count exceeds {X5CHAIN_MAX_CHAIN_CERTS} limit"
        )));
    }

    Ok(ders)
}

fn verify_with_x5chain_internal(
    chain_ders: &[Vec<u8>],
    anchors: &TrustAnchors,
) -> Result<Vec<X509>, CorimError> {
    if chain_ders.is_empty() {
        return Err(CorimError::X5chain(X5chainError::EmptyChain));
    }

    for der in chain_ders {
        if der.len() > X5CHAIN_MAX_CERT_DER_BYTES {
            return Err(CorimError::custom(format!(
                "decoding x5chain: certificate exceeds {X5CHAIN_MAX_CERT_DER_BYTES} byte limit"
            )));
        }
    }

    let chain: Vec<X509> = chain_ders
        .iter()
        .map(|der| certificate_from_der(der))
        .collect::<Result<_, _>>()?;
    validate_signing_certificate(&chain[0])?;

    let now_secs = validation_time(anchors)?;
    let verified_chain = verify_pkix_chain(&chain, anchors, now_secs)?;
    // CRL only when `anchors.crls` is non-empty (see `check_chain_revocation`).
    check_chain_revocation(&verified_chain, &anchors.crls, anchors.crl_policy, now_secs)?;

    Ok(verified_chain)
}

/// PKIX + optional CRL on a presented DER chain (leaf first). **No COSE verification.**
///
/// For a decoded signed CoRIM, use [`SignedCorim::verify_with_x5chain`] instead — same name,
/// different symbol (method runs the full x5chain → COSE pipeline).
pub fn verify_with_x5chain(
    chain_ders: &[impl AsRef<[u8]>],
    anchors: &TrustAnchors,
) -> Result<(), CorimError> {
    let ders: Vec<Vec<u8>> = chain_ders.iter().map(|der| der.as_ref().to_vec()).collect();
    verify_with_x5chain_internal(&ders, anchors).map(|_| ())
}

impl SignedCorim<'_> {
    /// Returns DER-encoded certificates from the x5chain in order, starting with
    /// the signing (leaf) certificate.
    pub fn x509_certificate_ders(&self) -> Result<Vec<Vec<u8>>, CorimError> {
        let Some(ref x5chain) = self.x5chain else {
            return Err(CorimError::X5chain(X5chainError::HeaderNotSet));
        };

        x5chain_flat_certificate_ders(x5chain)
    }

    /// Validates the embedded x5chain: leaf policy → PKIX → post-PKIX CRL when
    /// `anchors.crls` is non-empty (per [`TrustAnchors::crl_policy`]) → COSE Sign1
    /// verify with the signing certificate public key.
    ///
    /// Unlike [`Self::verify_signature`], this path does **not** enforce
    /// `corim-meta.signature-validity`.
    ///
    /// Callers that verify with an external JWK or PEM public key should use
    /// [`Self::verify_signature`] instead; PKIX and `--trust-anchors` flags do not
    /// apply on that path.
    pub fn verify_with_x5chain(&self, anchors: &TrustAnchors) -> Result<(), CorimError> {
        let chain_ders = self.x509_certificate_ders()?;
        let verified_chain = verify_with_x5chain_internal(&chain_ders, anchors)?;

        let verifier = OpensslSigner::public_key_from_x509(&verified_chain[0])?;
        self.verify_cose_signature_only(verifier).map_err(|err| {
            CorimError::X5chain(X5chainError::CoseSignatureVerificationFailed(
                err.to_string(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    // SPDX-License-Identifier: MIT

    use super::*;
    use crate::core::{Bytes, CoseAlgorithm, OneOrMore};
    use crate::corim::{Corim, CorimMap, CorimMetaMap, SignedCorim, SignedCorimBuilder};
    use crate::openssl::certificate_from_der;
    use crate::openssl::validate_signing_certificate;
    use crate::openssl::OpensslSigner;
    use crate::{CorimError, X5chainCrlLoadErrorKind, X5chainError};
    use openssl::x509::X509;
    use serial_test::serial;
    use std::fs::File;
    use std::path::PathBuf;

    fn cert_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/x509/certs")
            .join(name)
    }

    fn test_data_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name)
    }

    fn assert_x5chain_verification_failed_contains(err: CorimError, needle: &str) {
        match err {
            CorimError::X5chain(X5chainError::VerificationFailed(reason)) => {
                assert!(
                    reason.contains(needle),
                    "expected reason containing {needle:?}, got: {reason}"
                );
            }
            other => panic!("expected X5chainVerificationFailed, got: {other}"),
        }
    }

    fn assert_custom_error_contains(err: CorimError, needle: &str) {
        match err {
            CorimError::Custom(message) => {
                assert!(
                    message.contains(needle),
                    "expected message containing {needle:?}, got: {message}"
                );
            }
            other => panic!("expected Custom, got: {other}"),
        }
    }

    fn load_cert(name: &str) -> X509 {
        let der = chain_ders(&[name]).pop().unwrap();
        certificate_from_der(&der).unwrap()
    }

    fn chain_ders(names: &[&str]) -> Vec<Vec<u8>> {
        names
            .iter()
            .map(|name| {
                let data = std::fs::read(cert_path(name)).unwrap();
                certificate_der_from_pem_or_der(&data).unwrap()
            })
            .collect()
    }

    fn trust_anchors_with_test_anchor() -> TrustAnchors {
        TrustAnchors::with_anchors(vec![load_cert("root.cert.pem")])
    }

    fn with_ssl_cert_file<F: FnOnce()>(cert_pem: &[u8], f: F) {
        use std::sync::Mutex;

        // Mutates process-global SSL_CERT_FILE/SSL_CERT_DIR; paired with #[serial] on callers
        // so parallel `cargo test` workers do not race on these variables.
        static ENV_LOCK: Mutex<()> = Mutex::new(());

        let _guard = ENV_LOCK.lock().unwrap();

        let tmp =
            std::env::temp_dir().join(format!("corim-rs-system-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let cert_path = tmp.join("root.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();

        let prev_file = std::env::var("SSL_CERT_FILE").ok();
        let prev_dir = std::env::var("SSL_CERT_DIR").ok();

        // SAFETY: guarded by ENV_LOCK so no concurrent env mutation in tests.
        unsafe {
            std::env::set_var("SSL_CERT_FILE", &cert_path);
            std::env::remove_var("SSL_CERT_DIR");
        }

        /// Restores env vars and cleans up temp dir on drop, even if the test panics.
        struct EnvRestore {
            prev_file: Option<String>,
            prev_dir: Option<String>,
            tmp: std::path::PathBuf,
        }

        impl Drop for EnvRestore {
            fn drop(&mut self) {
                // SAFETY: guarded by ENV_LOCK so no concurrent env mutation in tests.
                unsafe {
                    match &self.prev_file {
                        Some(v) => std::env::set_var("SSL_CERT_FILE", v),
                        None => std::env::remove_var("SSL_CERT_FILE"),
                    }
                    match &self.prev_dir {
                        Some(v) => std::env::set_var("SSL_CERT_DIR", v),
                        None => std::env::remove_var("SSL_CERT_DIR"),
                    }
                }
                let _ = std::fs::remove_dir_all(&self.tmp);
            }
        }

        let _restore = EnvRestore {
            prev_file,
            prev_dir,
            tmp: tmp.clone(),
        };

        f();
    }

    enum X5chainIntermediateLayout {
        SeparateElements,
        ConcatenatedInOneElement,
    }

    fn build_signed_x5chain_corim(
        leaf_der: Vec<u8>,
        intermediate_ders: Vec<Vec<u8>>,
        signer_pem: &[u8],
        layout: X5chainIntermediateLayout,
    ) -> Vec<u8> {
        let corim_map = {
            let file = File::open(test_data_path("good-corim.json")).unwrap();
            CorimMap::from_json(file).unwrap()
        };
        let meta = {
            let file = File::open(test_data_path("meta.json")).unwrap();
            CorimMetaMap::from_json(file).unwrap()
        };

        let x5chain = match layout {
            X5chainIntermediateLayout::SeparateElements => {
                let mut chain: Vec<Bytes> = vec![leaf_der.into()];
                for der in intermediate_ders {
                    chain.push(der.into());
                }
                match chain.len() {
                    1 => OneOrMore::One(chain.into_iter().next().unwrap()),
                    _ => OneOrMore::More(chain),
                }
            }
            X5chainIntermediateLayout::ConcatenatedInOneElement => {
                let mut inter_concat = Vec::new();
                for der in intermediate_ders {
                    inter_concat.extend_from_slice(&der);
                }
                OneOrMore::More(vec![leaf_der.into(), inter_concat.into()])
            }
        };

        let signer = OpensslSigner::private_key_from_pem(signer_pem).unwrap();

        let signed = SignedCorimBuilder::new()
            .alg(CoseAlgorithm::ES256)
            .kid(b"test-kid".to_vec())
            .x5chain(x5chain)
            .meta(meta)
            .corim_map(corim_map)
            .build_and_sign(signer)
            .unwrap();

        Corim::from(signed).to_cbor().unwrap()
    }

    fn build_signed_corim_with_chain(
        leaf_der: &[u8],
        intermediates: &[Vec<u8>],
        signer_pem: &[u8],
    ) -> Vec<u8> {
        build_signed_x5chain_corim(
            leaf_der.to_vec(),
            intermediates.to_vec(),
            signer_pem,
            X5chainIntermediateLayout::SeparateElements,
        )
    }

    fn build_signed_x5chain_corim_from_test_certs(intermediates: &[&str]) -> Vec<u8> {
        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let intermediate_ders: Vec<Vec<u8>> = intermediates
            .iter()
            .map(|name| chain_ders(&[name])[0].clone())
            .collect();
        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        build_signed_x5chain_corim(
            leaf_der,
            intermediate_ders,
            &signer_pem,
            X5chainIntermediateLayout::SeparateElements,
        )
    }

    fn build_signed_x5chain_corim_concat_intermediates(intermediates: &[&str]) -> Vec<u8> {
        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let intermediate_ders: Vec<Vec<u8>> = intermediates
            .iter()
            .map(|name| chain_ders(&[name])[0].clone())
            .collect();
        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        build_signed_x5chain_corim(
            leaf_der,
            intermediate_ders,
            &signer_pem,
            X5chainIntermediateLayout::ConcatenatedInOneElement,
        )
    }

    fn build_signed_corim_without_x5chain() -> Vec<u8> {
        let corim_map = {
            let file = File::open(test_data_path("good-corim.json")).unwrap();
            CorimMap::from_json(file).unwrap()
        };
        let meta = {
            let file = File::open(test_data_path("meta.json")).unwrap();
            CorimMetaMap::from_json(file).unwrap()
        };

        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let signer = OpensslSigner::private_key_from_pem(&signer_pem).unwrap();

        let signed = SignedCorimBuilder::new()
            .alg(CoseAlgorithm::ES256)
            .kid(b"test-kid".to_vec())
            .meta(meta)
            .corim_map(corim_map)
            .build_and_sign(signer)
            .unwrap();

        Corim::from(signed).to_cbor().unwrap()
    }

    fn signed_from_cbor(cbor: &[u8]) -> SignedCorim<'static> {
        let corim = Corim::from_cbor(cbor).unwrap();
        corim.as_signed().expect("expected signed CoRIM")
    }

    #[test]
    fn verify_x509_chain_ok() {
        verify_x509_chain(&chain_ders(&["int.cert.pem", "root.cert.pem"])).unwrap();
    }

    #[test]
    fn verify_x509_chain_single_cert() {
        verify_x509_chain(&chain_ders(&["root.cert.pem"])).unwrap();
    }

    #[test]
    fn verify_x509_chain_empty() {
        let err = verify_x509_chain(&[] as &[Vec<u8>]).unwrap_err();
        assert!(matches!(err, CorimError::X5chain(X5chainError::EmptyChain)));
    }

    #[test]
    fn verify_x509_chain_bad_order() {
        let err = verify_x509_chain(&chain_ders(&["root.cert.pem", "int.cert.pem"])).unwrap_err();
        assert!(matches!(
            err,
            CorimError::X5chain(X5chainError::InvalidCertificateSignature(_))
        ));
    }

    #[test]
    fn verify_with_x5chain_untrusted_anchor() {
        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem", "root.cert.pem"]);
        let anchors = TrustAnchors::with_anchors(Vec::new());
        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert_x5chain_verification_failed_contains(err, "no trusted anchors configured");
    }

    #[test]
    fn verify_with_x5chain_explicit_intermediate_anchor_ok() {
        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem", "root.cert.pem"]);
        let anchors = TrustAnchors::with_anchors(vec![load_cert("int.cert.pem")]);
        verify_with_x5chain(&chain, &anchors).unwrap();
    }

    #[test]
    fn verify_with_x5chain_wrong_explicit_anchor_fails() {
        let chain = chain_ders(&["leaf.cert.pem"]);
        let anchors = TrustAnchors::with_anchors(vec![load_cert("root.cert.pem")]);

        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert_x5chain_verification_failed_contains(err, "unable to get local issuer certificate");
    }

    #[test]
    fn load_trust_anchors_explicit_paths_only() {
        let anchor_pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        let anchors = load_trust_anchors(
            |path| {
                if path != "anchor.pem" {
                    panic!("unexpected path {path}");
                }
                Ok(anchor_pem.clone())
            },
            &["anchor.pem"],
            &[] as &[&str],
        )
        .unwrap();

        assert_eq!(anchors.anchors.as_ref().map(|a| a.len()), Some(1));
    }

    #[test]
    fn load_trust_anchors_wrong_anchor_e2e_fails_pkix() {
        use crl_helpers::make_ca_named;

        let (wrong_ca, _) = make_ca_named("Wrong Anchor CA");
        let wrong_der = wrong_ca.to_der().unwrap();
        let anchors = load_trust_anchors(
            |path| {
                if path != "wrong.der" {
                    panic!("unexpected path {path}");
                }
                Ok(wrong_der.clone())
            },
            &["wrong.der"],
            &[] as &[&str],
        )
        .unwrap();

        let cbor = build_signed_x5chain_corim_from_test_certs(&["int.cert.pem", "root.cert.pem"]);
        let signed = signed_from_cbor(&cbor);
        let err = signed.verify_with_x5chain(&anchors).unwrap_err();
        assert_x5chain_verification_failed_contains(
            err,
            "self-signed certificate in certificate chain",
        );
    }

    #[test]
    fn signed_corim_verify_with_x5chain_rejects_expired_leaf() {
        let cbor = build_signed_x5chain_corim_from_test_certs(&["int.cert.pem", "root.cert.pem"]);
        let signed = signed_from_cbor(&cbor);
        let anchors = trust_anchors_with_test_anchor().with_validation_time(4_102_444_800);
        let err = signed.verify_with_x5chain(&anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CertificateExpired)),
            "expected expired certificate error, got: {err}"
        );
    }

    #[test]
    fn signed_corim_verify_with_x5chain_rejects_revoked_leaf() {
        use crl_helpers::{make_crl_revoking_leaf, make_intermediate_pki, make_valid_chain_crls};

        let pki = make_intermediate_pki();
        let mut crls = make_valid_chain_crls(&pki);
        crls[0] = make_crl_revoking_leaf(&pki.intermediate, &pki.intermediate_key, &pki.leaf);
        let leaf_pem = pki._leaf_key.serialize_pem();
        let cbor = build_signed_corim_with_chain(
            &pki.leaf.to_der().unwrap(),
            &[pki.intermediate.to_der().unwrap()],
            leaf_pem.as_bytes(),
        );
        let signed = signed_from_cbor(&cbor);
        let anchors = TrustAnchors::with_anchors_and_crls(vec![pki.root.clone()], crls);
        let err = signed.verify_with_x5chain(&anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CertificateRevoked)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn signed_corim_verify_with_x5chain_ok() {
        let cbor = build_signed_x5chain_corim_from_test_certs(&["int.cert.pem", "root.cert.pem"]);
        let signed = signed_from_cbor(&cbor);
        signed
            .verify_with_x5chain(&trust_anchors_with_test_anchor())
            .unwrap();
    }

    #[test]
    fn signed_corim_verify_with_x5chain_ignores_expired_signature_validity() {
        let corim_map = {
            let file = File::open(test_data_path("good-corim.json")).unwrap();
            CorimMap::from_json(file).unwrap()
        };
        let mut meta = {
            let file = File::open(test_data_path("meta.json")).unwrap();
            CorimMetaMap::from_json(file).unwrap()
        };
        meta.signature_validity = Some(crate::corim::ValidityMap {
            not_before: None,
            not_after: 1.into(),
        });

        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let int_der = chain_ders(&["int.cert.pem"])[0].clone();
        let x5chain = OneOrMore::More(vec![leaf_der.into(), int_der.into()]);
        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let signer = OpensslSigner::private_key_from_pem(&signer_pem).unwrap();

        let signed = SignedCorimBuilder::new()
            .alg(CoseAlgorithm::ES256)
            .kid(b"test-kid".to_vec())
            .x5chain(x5chain)
            .meta(meta)
            .corim_map(corim_map)
            .build_and_sign(signer)
            .unwrap();

        signed
            .verify_with_x5chain(&trust_anchors_with_test_anchor())
            .expect("x5chain path must not enforce corim-meta signature-validity");

        let leaf_key = OpensslSigner::private_key_from_pem(&signer_pem).unwrap();
        let err = signed.verify_signature(leaf_key).unwrap_err();
        assert!(
            matches!(err, CorimError::OutsideValidityPeriod),
            "verify_signature must still enforce signature-validity, got: {err}"
        );
    }

    #[test]
    fn signed_corim_verify_with_x5chain_intermediate_only_chain() {
        let cbor = build_signed_x5chain_corim_from_test_certs(&["int.cert.pem"]);
        let signed = signed_from_cbor(&cbor);
        signed
            .verify_with_x5chain(&trust_anchors_with_test_anchor())
            .unwrap();
    }

    #[test]
    fn signed_corim_verify_with_x5chain_concatenated_intermediates() {
        let cbor =
            build_signed_x5chain_corim_concat_intermediates(&["int.cert.pem", "root.cert.pem"]);
        let signed = signed_from_cbor(&cbor);
        signed
            .verify_with_x5chain(&trust_anchors_with_test_anchor())
            .unwrap();
    }

    #[test]
    #[serial]
    fn signed_corim_verify_with_x5chain_system_store_contains_root() {
        let root_pem = std::fs::read(cert_path("root.cert.pem")).unwrap();

        with_ssl_cert_file(&root_pem, || {
            let cbor = build_signed_x5chain_corim_from_test_certs(&["int.cert.pem"]);
            let signed = signed_from_cbor(&cbor);

            let anchors = load_trust_anchors(
                |_| panic!("read_file should not be called when trust_anchor_paths is empty"),
                &[] as &[&str],
                &[] as &[&str],
            )
            .unwrap();
            assert!(anchors.anchors.is_none());

            signed.verify_with_x5chain(&anchors).unwrap();
        });
    }

    #[test]
    fn signed_corim_verify_with_x5chain_no_x5chain() {
        let cbor = build_signed_corim_without_x5chain();
        let signed = signed_from_cbor(&cbor);
        let err = signed
            .verify_with_x5chain(&trust_anchors_with_test_anchor())
            .unwrap_err();
        assert!(matches!(
            err,
            CorimError::X5chain(X5chainError::HeaderNotSet)
        ));
    }

    #[test]
    fn signed_corim_verify_with_x5chain_tampered_payload() {
        let mut cbor = build_signed_x5chain_corim_from_test_certs(&["int.cert.pem"]);
        let last = cbor.len() - 1;
        cbor[last] ^= 0xff;

        let signed = signed_from_cbor(&cbor);
        let err = signed
            .verify_with_x5chain(&trust_anchors_with_test_anchor())
            .unwrap_err();
        assert!(
            matches!(
                err,
                CorimError::X5chain(X5chainError::CoseSignatureVerificationFailed(_))
            ),
            "expected signature verification failure, got: {err}"
        );
        if let CorimError::X5chain(X5chainError::CoseSignatureVerificationFailed(detail)) = err {
            assert!(
                !detail.is_empty(),
                "COSE signature failure detail must be non-empty"
            );
        }
    }

    #[test]
    fn validate_signing_certificate_rejects_ca() {
        let root = load_cert("root.cert.pem");
        let err = validate_signing_certificate(&root).unwrap_err();
        assert!(matches!(
            err,
            CorimError::X5chain(X5chainError::SigningCertMustNotBeCa)
        ));
    }

    #[test]
    fn signed_corim_verify_with_x5chain_signing_cert_is_ca_from_cose() {
        let root = load_cert("root.cert.pem");
        let root_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let cbor = build_signed_corim_with_chain(&root.to_der().unwrap(), &[], &root_pem);
        let signed = signed_from_cbor(&cbor);
        let err = signed
            .verify_with_x5chain(&trust_anchors_with_test_anchor())
            .unwrap_err();
        assert!(matches!(
            err,
            CorimError::X5chain(X5chainError::SigningCertMustNotBeCa)
        ));
    }

    #[test]
    fn certificate_der_from_pem_or_der_der() {
        let der = chain_ders(&["root.cert.pem"]).pop().unwrap();
        let parsed = certificate_der_from_pem_or_der(&der).unwrap();
        assert_eq!(parsed, der);
    }

    #[test]
    fn certificate_der_from_pem_or_der_rejects_der_trailing_data() {
        let mut der = chain_ders(&["root.cert.pem"]).pop().unwrap();
        der.push(0);
        let err = certificate_der_from_pem_or_der(&der).unwrap_err();
        assert_custom_error_contains(err, "trailing data after DER");
    }

    #[test]
    fn certificate_der_from_pem_or_der_pem() {
        let pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        let expected_der = chain_ders(&["root.cert.pem"]).pop().unwrap();
        let parsed = certificate_der_from_pem_or_der(&pem).unwrap();
        assert_eq!(parsed, expected_der);
    }

    #[test]
    fn load_trust_anchors_dedupes_duplicate_trust_anchors() {
        let anchor_pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        let anchor_der = certificate_der_from_pem_or_der(&anchor_pem).unwrap();

        let anchors = load_trust_anchors(
            |_| Ok(anchor_pem.clone()),
            &["anchor-a.pem", "anchor-b.pem"],
            &[] as &[&str],
        )
        .unwrap();

        use crate::openssl::cert_to_der;
        let matching = anchors
            .anchors
            .as_ref()
            .map(|anchors| {
                anchors
                    .iter()
                    .filter(|cert| cert_to_der(cert).ok().as_deref() == Some(anchor_der.as_slice()))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            matching, 1,
            "duplicate trust-anchor DER must appear once in anchors"
        );

        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem"]);
        verify_with_x5chain(&chain, &anchors).expect("deduped anchors must verify chain");
    }

    #[test]
    fn trust_anchors_from_der_anchors_and_crls_ok() {
        let root_der = chain_ders(&["root.cert.pem"])[0].clone();
        let anchors = TrustAnchors::from_der_anchors_and_crls(vec![root_der], vec![]).unwrap();
        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem"]);
        verify_with_x5chain(&chain, &anchors).unwrap();
    }

    #[test]
    fn load_trust_anchors_loads_pem_trust_anchor_bundle() {
        let root_pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        let int_pem = std::fs::read(cert_path("int.cert.pem")).unwrap();
        let bundle: Vec<u8> = [root_pem.as_slice(), int_pem.as_slice()].concat();

        let anchors =
            load_trust_anchors(|_| Ok(bundle.clone()), &["bundle.pem"], &[] as &[&str]).unwrap();

        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem"]);
        verify_with_x5chain(&chain, &anchors).expect("bundle anchors should verify chain");
    }

    mod crl_helpers {
        use crate::openssl::crl_from_der;
        use openssl::x509::{X509Crl, X509};
        use rcgen::{
            BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
            DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber,
        };
        use time::{Duration, OffsetDateTime};

        /// Signing material for dynamically generated test CAs.
        pub(super) struct CaSigningKey {
            pub cert: Certificate,
            pub key_pair: KeyPair,
        }

        pub(super) struct TestPki {
            pub root: X509,
            pub root_key: CaSigningKey,
            pub intermediate: X509,
            pub intermediate_key: CaSigningKey,
            pub leaf: X509,
            pub _leaf_key: KeyPair,
        }

        fn now() -> OffsetDateTime {
            OffsetDateTime::now_utc()
        }

        fn crl_params(
            this_update: OffsetDateTime,
            next_update: OffsetDateTime,
            revoked_certs: Vec<RevokedCertParams>,
        ) -> CertificateRevocationListParams {
            CertificateRevocationListParams {
                this_update,
                next_update,
                crl_number: SerialNumber::from(1u64),
                issuing_distribution_point: None,
                revoked_certs,
                key_identifier_method: KeyIdMethod::Sha256,
            }
        }

        pub(super) fn make_ca() -> (X509, CaSigningKey) {
            make_ca_named("Test CA")
        }

        pub(super) fn make_ca_named(common_name: &str) -> (X509, CaSigningKey) {
            let key_pair = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.serial_number = Some(SerialNumber::from(1u64));
            let now = now();
            params.not_before = now - Duration::hours(1);
            params.not_after = now + Duration::hours(1);
            let cert = params.self_signed(&key_pair).unwrap();
            let x509 = X509::from_der(cert.der()).unwrap();
            (x509, CaSigningKey { cert, key_pair })
        }

        pub(super) fn make_intermediate_pki() -> TestPki {
            let (root, root_key) = make_ca_named("Root CA");
            let intermediate_key_pair = KeyPair::generate().unwrap();
            let mut intermediate_params = CertificateParams::default();
            intermediate_params
                .distinguished_name
                .push(DnType::CommonName, "Intermediate CA");
            intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            intermediate_params.key_usages =
                vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            intermediate_params.serial_number = Some(SerialNumber::from(2u64));
            let now = now();
            intermediate_params.not_before = now - Duration::hours(1);
            intermediate_params.not_after = now + Duration::hours(1);
            let intermediate_cert = intermediate_params
                .signed_by(&intermediate_key_pair, &root_key.cert, &root_key.key_pair)
                .unwrap();
            let intermediate = X509::from_der(intermediate_cert.der()).unwrap();
            let intermediate_key = CaSigningKey {
                cert: intermediate_cert,
                key_pair: intermediate_key_pair,
            };

            let leaf_key = KeyPair::generate().unwrap();
            let mut leaf_params = CertificateParams::default();
            leaf_params
                .distinguished_name
                .push(DnType::CommonName, "Leaf");
            leaf_params.serial_number = Some(SerialNumber::from(3u64));
            leaf_params.not_before = now - Duration::hours(1);
            leaf_params.not_after = now + Duration::hours(1);
            leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let leaf_cert = leaf_params
                .signed_by(
                    &leaf_key,
                    &intermediate_key.cert,
                    &intermediate_key.key_pair,
                )
                .unwrap();
            let leaf = X509::from_der(leaf_cert.der()).unwrap();

            TestPki {
                root,
                root_key,
                intermediate,
                intermediate_key,
                leaf,
                _leaf_key: leaf_key,
            }
        }

        pub(super) fn make_leaf(_ca: &X509, ca_key: &CaSigningKey) -> (X509, KeyPair) {
            let leaf_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, "Test Leaf");
            params.serial_number = Some(SerialNumber::from(2u64));
            let now = now();
            params.not_before = now - Duration::hours(1);
            params.not_after = now + Duration::hours(1);
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let cert = params
                .signed_by(&leaf_key, &ca_key.cert, &ca_key.key_pair)
                .unwrap();
            (X509::from_der(cert.der()).unwrap(), leaf_key)
        }

        fn leaf_serial(leaf: &X509) -> SerialNumber {
            let bytes = leaf.serial_number().to_bn().unwrap().to_vec();
            SerialNumber::from(bytes)
        }

        fn intermediate_serial(intermediate: &X509) -> SerialNumber {
            let bytes = intermediate.serial_number().to_bn().unwrap().to_vec();
            SerialNumber::from(bytes)
        }

        pub(super) fn make_crl_revoking_leaf(
            _ca: &X509,
            ca_key: &CaSigningKey,
            leaf: &X509,
        ) -> X509Crl {
            let now = now();
            let params = crl_params(
                now - Duration::minutes(1),
                now + Duration::hours(1),
                vec![RevokedCertParams {
                    serial_number: leaf_serial(leaf),
                    revocation_time: now - Duration::minutes(1),
                    reason_code: None,
                    invalidity_date: None,
                }],
            );
            let crl = params.signed_by(&ca_key.cert, &ca_key.key_pair).unwrap();
            crl_from_der(crl.der()).unwrap()
        }

        pub(super) fn make_crl_revoking_intermediate(
            _root: &X509,
            root_key: &CaSigningKey,
            intermediate: &X509,
        ) -> X509Crl {
            let now = now();
            let params = crl_params(
                now - Duration::minutes(1),
                now + Duration::hours(1),
                vec![RevokedCertParams {
                    serial_number: intermediate_serial(intermediate),
                    revocation_time: now - Duration::minutes(1),
                    reason_code: None,
                    invalidity_date: None,
                }],
            );
            let crl = params
                .signed_by(&root_key.cert, &root_key.key_pair)
                .unwrap();
            crl_from_der(crl.der()).unwrap()
        }

        pub(super) fn make_expired_crl(_ca: &X509, ca_key: &CaSigningKey) -> X509Crl {
            let now = now();
            let params = crl_params(now - Duration::hours(2), now - Duration::hours(1), vec![]);
            let crl = params.signed_by(&ca_key.cert, &ca_key.key_pair).unwrap();
            crl_from_der(crl.der()).unwrap()
        }

        pub(super) fn make_valid_crl(_ca: &X509, ca_key: &CaSigningKey) -> X509Crl {
            let now = now();
            let params = crl_params(now - Duration::minutes(1), now + Duration::hours(1), vec![]);
            let crl = params.signed_by(&ca_key.cert, &ca_key.key_pair).unwrap();
            crl_from_der(crl.der()).unwrap()
        }

        /// Valid CRLs for each non-anchor issuer on a three-tier test chain
        /// (intermediate → leaf; root → intermediate).
        pub(super) fn make_valid_chain_crls(pki: &TestPki) -> Vec<X509Crl> {
            vec![
                make_valid_crl(&pki.intermediate, &pki.intermediate_key),
                make_valid_crl(&pki.root, &pki.root_key),
            ]
        }

        pub(super) fn make_not_yet_valid_crl(_ca: &X509, ca_key: &CaSigningKey) -> X509Crl {
            let now = now();
            let params = crl_params(now + Duration::hours(1), now + Duration::hours(2), vec![]);
            let crl = params.signed_by(&ca_key.cert, &ca_key.key_pair).unwrap();
            crl_from_der(crl.der()).unwrap()
        }

        /// CRL signed by `ca_key` with `lastUpdate` set and no `nextUpdate` field.
        pub(super) fn make_crl_without_next_update(ca: &X509, ca_key: &CaSigningKey) -> X509Crl {
            use foreign_types::ForeignType;
            use openssl::asn1::Asn1Time;
            use openssl::hash::MessageDigest;
            use openssl::pkey::PKey;
            use openssl_sys as ffi;

            unsafe {
                let crl_ptr = ffi::X509_CRL_new();
                assert!(!crl_ptr.is_null());
                let version_ok = ffi::X509_CRL_set_version(crl_ptr, 1);
                assert_eq!(version_ok, 1);
                let issuer = ffi::X509_get_subject_name(ca.as_ptr());
                let issuer_ok = ffi::X509_CRL_set_issuer_name(crl_ptr, issuer);
                assert_eq!(issuer_ok, 1);
                let last_update = Asn1Time::days_from_now(0).unwrap();
                let last_update_ok =
                    ffi::X509_CRL_set1_lastUpdate(crl_ptr, last_update.as_ptr() as *const _);
                assert_eq!(last_update_ok, 1);
                let pem = ca_key.key_pair.serialize_pem();
                let pkey = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
                let sign_ok =
                    ffi::X509_CRL_sign(crl_ptr, pkey.as_ptr(), MessageDigest::sha256().as_ptr());
                assert_ne!(sign_ok, 0, "X509_CRL_sign failed");
                let der_len = ffi::i2d_X509_CRL(crl_ptr, std::ptr::null_mut());
                assert!(der_len > 0);
                let mut der = vec![0u8; der_len as usize];
                let mut der_ptr = der.as_mut_ptr();
                let written = ffi::i2d_X509_CRL(crl_ptr, &mut der_ptr);
                assert_eq!(written, der_len);
                ffi::X509_CRL_free(crl_ptr);
                let crl = crl_from_der(&der).unwrap();
                assert!(crl.next_update().is_none());
                crl
            }
        }

        pub(super) fn make_leaf_zero_key_usage(_ca: &X509, ca_key: &CaSigningKey) -> X509 {
            let leaf_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, "No KU Leaf");
            params.serial_number = Some(SerialNumber::from(5u64));
            let now = now();
            params.not_before = now - Duration::hours(1);
            params.not_after = now + Duration::hours(1);
            let cert = params
                .signed_by(&leaf_key, &ca_key.cert, &ca_key.key_pair)
                .unwrap();
            X509::from_der(cert.der()).unwrap()
        }
    }

    #[test]
    fn load_trust_anchors_pem_crl_e2e_revokes_leaf() {
        use crl_helpers::{make_ca, make_crl_revoking_leaf, make_leaf};

        let (ca, ca_key) = make_ca();
        let (leaf, _) = make_leaf(&ca, &ca_key);
        let crl = make_crl_revoking_leaf(&ca, &ca_key, &leaf);
        let pem = crl.to_pem().unwrap();
        let ca_der = ca.to_der().unwrap();
        let chain = vec![leaf.to_der().unwrap(), ca.to_der().unwrap()];

        let anchors = load_trust_anchors(
            |path| match path {
                "anchor.der" => Ok(ca_der.clone()),
                "issuer.crl" => Ok(pem.clone()),
                _ => panic!("unexpected path {path}"),
            },
            &["anchor.der"],
            &["issuer.crl"],
        )
        .unwrap();

        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CertificateRevoked)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_trust_anchors_loads_crls() {
        use crl_helpers::{make_intermediate_pki, make_valid_crl};

        let pki = make_intermediate_pki();
        let crl = make_valid_crl(&pki.intermediate, &pki.intermediate_key);
        let crl_der = crl.to_der().unwrap();

        let anchors = load_trust_anchors(
            |path| match path {
                "anchor.der" => Ok(pki.root.to_der().unwrap()),
                "issuer.crl" => Ok(crl_der.clone()),
                _ => panic!("unexpected path {path}"),
            },
            &["anchor.der"],
            &["issuer.crl"],
        )
        .unwrap();

        assert_eq!(anchors.crls.len(), 1);
        assert_eq!(
            anchors.crls[0].to_der().ok().as_deref(),
            Some(crl_der.as_slice())
        );
    }

    #[test]
    fn verify_with_x5chain_rejects_expired_crl() {
        use crl_helpers::{make_ca, make_expired_crl, make_leaf};

        let (ca, ca_key) = make_ca();
        let (leaf, _) = make_leaf(&ca, &ca_key);
        let expired_crl = make_expired_crl(&ca, &ca_key);
        let chain = vec![leaf.to_der().unwrap(), ca.to_der().unwrap()];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![ca.clone()], vec![expired_crl]);

        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CrlExpired)),
            "expected expired CRL error, got: {err}"
        );
    }

    #[test]
    fn signed_corim_verify_with_x5chain_signing_key_mismatch() {
        use crl_helpers::make_intermediate_pki;

        let pki = make_intermediate_pki();
        let wrong_key = rcgen::KeyPair::generate().unwrap();
        let cbor = build_signed_corim_with_chain(
            &pki.leaf.to_der().unwrap(),
            &[pki.intermediate.to_der().unwrap()],
            wrong_key.serialize_pem().as_bytes(),
        );
        let signed = signed_from_cbor(&cbor);
        let anchors = TrustAnchors::with_anchors(vec![pki.root.clone()]);
        let err = signed.verify_with_x5chain(&anchors).unwrap_err();
        assert!(
            matches!(
                err,
                CorimError::X5chain(X5chainError::CoseSignatureVerificationFailed(_))
            ),
            "unexpected error: {err}"
        );
        if let CorimError::X5chain(X5chainError::CoseSignatureVerificationFailed(detail)) = err {
            assert!(
                !detail.is_empty(),
                "COSE signature failure detail must be non-empty"
            );
        }
    }

    #[test]
    fn verify_with_x5chain_revoked_intermediate_via_root_crl() {
        use crl_helpers::{make_crl_revoking_intermediate, make_intermediate_pki, make_valid_crl};

        let pki = make_intermediate_pki();
        let crls = vec![
            make_valid_crl(&pki.intermediate, &pki.intermediate_key),
            make_crl_revoking_intermediate(&pki.root, &pki.root_key, &pki.intermediate),
        ];
        let chain = vec![
            pki.leaf.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![pki.root.clone()], crls);
        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CertificateRevoked)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_with_x5chain_revoked_leaf_uses_verified_chain() {
        use crl_helpers::{
            make_ca_named, make_crl_revoking_leaf, make_intermediate_pki, make_valid_chain_crls,
        };

        let pki = make_intermediate_pki();
        let (unrelated_ca, _) = make_ca_named("Unrelated CA");
        let mut crls = make_valid_chain_crls(&pki);
        crls[0] = make_crl_revoking_leaf(&pki.intermediate, &pki.intermediate_key, &pki.leaf);
        let chain = vec![
            pki.leaf.to_der().unwrap(),
            unrelated_ca.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![pki.root.clone()], crls);
        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CertificateRevoked)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_with_x5chain_rejects_crl_without_next_update_under_strict() {
        use crl_helpers::{make_ca, make_crl_without_next_update, make_leaf};

        let (ca, ca_key) = make_ca();
        let (leaf, _) = make_leaf(&ca, &ca_key);
        let crl = make_crl_without_next_update(&ca, &ca_key);
        let chain = vec![leaf.to_der().unwrap(), ca.to_der().unwrap()];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![ca.clone()], vec![crl]);

        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CrlMissingNextUpdate)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_with_x5chain_crl_not_yet_valid_fails() {
        use crl_helpers::{make_ca, make_leaf, make_not_yet_valid_crl};

        let (ca, ca_key) = make_ca();
        let (leaf, _) = make_leaf(&ca, &ca_key);
        let crl = make_not_yet_valid_crl(&ca, &ca_key);
        let chain = vec![leaf.to_der().unwrap(), ca.to_der().unwrap()];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![ca.clone()], vec![crl]);
        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CrlNotYetValid)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_with_x5chain_permissive_skips_missing_issuer_crl() {
        use crl_helpers::{make_ca_named, make_leaf, make_valid_crl};

        let (chain_ca, chain_ca_key) = make_ca_named("Chain CA");
        let (leaf, _) = make_leaf(&chain_ca, &chain_ca_key);
        let (unrelated_ca, unrelated_key) = make_ca_named("Unrelated CA");
        let crl = make_valid_crl(&unrelated_ca, &unrelated_key);
        let chain = vec![leaf.to_der().unwrap(), chain_ca.to_der().unwrap()];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![chain_ca.clone()], vec![crl])
            .with_crl_policy(CrlPolicy::Permissive);

        verify_with_x5chain(&chain, &anchors).unwrap();
    }

    #[test]
    fn verify_with_x5chain_permissive_rejects_matching_crl_with_bad_signature() {
        use crl_helpers::{make_ca_named, make_leaf, make_valid_crl};

        let (chain_ca, chain_ca_key) = make_ca_named("Chain CA");
        let (leaf, _) = make_leaf(&chain_ca, &chain_ca_key);
        let (same_name_ca, same_name_key) = make_ca_named("Chain CA");
        let crl = make_valid_crl(&same_name_ca, &same_name_key);
        let chain = vec![leaf.to_der().unwrap(), chain_ca.to_der().unwrap()];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![chain_ca.clone()], vec![crl])
            .with_crl_policy(CrlPolicy::Permissive);

        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert_custom_error_contains(err, "CRL signature invalid");
    }

    #[test]
    fn verify_with_x5chain_fails_when_crls_do_not_cover_chain_issuers() {
        use crl_helpers::{make_ca_named, make_leaf, make_valid_crl};

        let (chain_ca, chain_ca_key) = make_ca_named("Chain CA");
        let (leaf, _) = make_leaf(&chain_ca, &chain_ca_key);
        let (unrelated_ca, unrelated_key) = make_ca_named("Unrelated CA");
        let crl = make_valid_crl(&unrelated_ca, &unrelated_key);
        let chain = vec![leaf.to_der().unwrap(), chain_ca.to_der().unwrap()];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![chain_ca.clone()], vec![crl]);

        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert_x5chain_verification_failed_contains(err, "unable to get certificate CRL");
    }

    #[test]
    fn verify_with_x5chain_strict_three_tier_missing_root_crl() {
        use crl_helpers::{make_intermediate_pki, make_valid_crl};

        let pki = make_intermediate_pki();
        let crl = make_valid_crl(&pki.intermediate, &pki.intermediate_key);
        let chain = vec![
            pki.leaf.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![pki.root.clone()], vec![crl]);

        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert_x5chain_verification_failed_contains(err, "unable to get certificate CRL");
    }

    #[test]
    fn verify_with_x5chain_ok_with_full_chain_crls_under_check_all() {
        use crl_helpers::{make_intermediate_pki, make_valid_chain_crls};

        let pki = make_intermediate_pki();
        let crls = make_valid_chain_crls(&pki);
        let chain = vec![
            pki.leaf.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![pki.root.clone()], crls);
        verify_with_x5chain(&chain, &anchors).unwrap();
    }

    #[test]
    fn verify_with_x5chain_ok_when_valid_crl_coexists_with_expired_sibling() {
        use crl_helpers::{make_expired_crl, make_intermediate_pki, make_valid_chain_crls};

        let pki = make_intermediate_pki();
        let expired = make_expired_crl(&pki.intermediate, &pki.intermediate_key);
        let mut crls = make_valid_chain_crls(&pki);
        crls.push(expired);
        let chain = vec![
            pki.leaf.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![pki.root.clone()], crls);
        verify_with_x5chain(&chain, &anchors).unwrap();
    }

    #[test]
    fn verify_with_x5chain_revoked_reported_before_expired_crl() {
        use crl_helpers::{
            make_crl_revoking_leaf, make_expired_crl, make_intermediate_pki, make_valid_crl,
        };

        let pki = make_intermediate_pki();
        let valid_revoking =
            make_crl_revoking_leaf(&pki.intermediate, &pki.intermediate_key, &pki.leaf);
        let expired = make_expired_crl(&pki.intermediate, &pki.intermediate_key);
        let crls = vec![
            expired,
            valid_revoking,
            make_valid_crl(&pki.root, &pki.root_key),
        ];
        let chain = vec![
            pki.leaf.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        let anchors = TrustAnchors::with_anchors_and_crls(vec![pki.root.clone()], crls);
        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CertificateRevoked)),
            "unexpected error: {err}"
        );
        assert!(
            !matches!(err, CorimError::X5chain(X5chainError::CrlExpired)),
            "revoked must be reported before expired CRL: {err}"
        );
    }

    #[test]
    fn verify_with_x5chain_fails_when_all_matching_crls_expired() {
        use crl_helpers::{make_expired_crl, make_intermediate_pki, make_valid_crl};

        let pki = make_intermediate_pki();
        let expired1 = make_expired_crl(&pki.intermediate, &pki.intermediate_key);
        let now = time::OffsetDateTime::now_utc();
        use rcgen::{CertificateRevocationListParams, KeyIdMethod, SerialNumber};
        let params = CertificateRevocationListParams {
            this_update: now - time::Duration::hours(3),
            next_update: now - time::Duration::hours(2),
            crl_number: SerialNumber::from(2u64),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl2 = params
            .signed_by(&pki.intermediate_key.cert, &pki.intermediate_key.key_pair)
            .unwrap();
        let expired2 = crl_from_der(crl2.der()).unwrap();

        let chain = vec![
            pki.leaf.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        let anchors = TrustAnchors::with_anchors_and_crls(
            vec![pki.root.clone()],
            vec![expired1, expired2, make_valid_crl(&pki.root, &pki.root_key)],
        );
        let err = verify_with_x5chain(&chain, &anchors).unwrap_err();
        assert!(
            matches!(err, CorimError::X5chain(X5chainError::CrlExpired)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_trust_anchors_read_file_error() {
        let err = match load_trust_anchors(
            |_| Err(CorimError::custom("read failed")),
            &["missing.der"],
            &[] as &[&str],
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected load error"),
        };
        assert!(
            matches!(err, CorimError::Custom(ref message) if message.contains("loading trust anchor from missing.der")
                && message.contains("read failed")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_trust_anchors_invalid_trust_anchor_parse() {
        let err = match load_trust_anchors(
            |_| Ok(b"not-a-cert".to_vec()),
            &["bad.der"],
            &[] as &[&str],
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected parse error"),
        };
        assert_custom_error_contains(err, "parsing trust anchor from bad.der");
    }

    #[test]
    fn load_trust_anchors_invalid_crl_parse() {
        let anchor_pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        let err = match load_trust_anchors(
            |path| match path {
                "anchor.der" => Ok(anchor_pem.clone()),
                "bad.crl" => Ok(b"not-a-crl".to_vec()),
                _ => panic!("unexpected path {path}"),
            },
            &["anchor.der"],
            &["bad.crl"],
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected CRL parse error"),
        };
        assert!(
            matches!(
                err,
                CorimError::X5chain(X5chainError::CrlLoadError { ref path, .. })
                    if path == "bad.crl"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_trust_anchors_loads_pem_crl_with_leading_whitespace() {
        use crl_helpers::{make_ca, make_valid_crl};

        let (ca, ca_key) = make_ca();
        let pem = make_valid_crl(&ca, &ca_key).to_pem().unwrap();
        let padded = [b"\n \t".as_slice(), pem.as_slice()].concat();

        let anchors = load_trust_anchors(
            |path| match path {
                "anchor.der" => Ok(ca.to_der().unwrap()),
                "crl.pem" => Ok(padded.clone()),
                _ => panic!("unexpected path {path}"),
            },
            &["anchor.der"],
            &["crl.pem"],
        )
        .unwrap();

        assert_eq!(anchors.crls.len(), 1);
    }

    #[test]
    fn load_trust_anchors_loads_pem_crl_bundle() {
        use crl_helpers::{make_intermediate_pki, make_valid_crl};

        let pki = make_intermediate_pki();
        let first = make_valid_crl(&pki.intermediate, &pki.intermediate_key);
        let second = make_valid_crl(&pki.root, &pki.root_key);
        let bundle = [first.to_pem().unwrap(), second.to_pem().unwrap()].concat();

        let anchors = load_trust_anchors(
            |path| match path {
                "anchor.der" => Ok(pki.root.to_der().unwrap()),
                "crls.pem" => Ok(bundle.clone()),
                _ => panic!("unexpected path {path}"),
            },
            &["anchor.der"],
            &["crls.pem"],
        )
        .unwrap();

        assert_eq!(anchors.anchors.as_ref().map(|a| a.len()), Some(1));
        assert_eq!(anchors.crls.len(), 2);
        let chain = vec![
            pki.leaf.to_der().unwrap(),
            pki.intermediate.to_der().unwrap(),
        ];
        verify_with_x5chain(&chain, &anchors).unwrap();
    }

    #[test]
    fn load_trust_anchors_rejects_non_crl_pem_blocks_in_crl_bundle() {
        use crl_helpers::{make_ca, make_valid_crl};

        let (ca, ca_key) = make_ca();
        let bundle = [
            ca.to_pem().unwrap(),
            make_valid_crl(&ca, &ca_key).to_pem().unwrap(),
        ]
        .concat();

        let err = match load_trust_anchors(
            |path| match path {
                "anchor.der" => Ok(ca.to_der().unwrap()),
                "crls.pem" => Ok(bundle.clone()),
                _ => panic!("unexpected path {path}"),
            },
            &["anchor.der"],
            &["crls.pem"],
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected CRL bundle parse error"),
        };

        assert!(matches!(
            &err,
            CorimError::X5chain(X5chainError::CrlLoadError {
                path,
                kind: X5chainCrlLoadErrorKind::InvalidPemBlockType(block_type),
            }) if path == "crls.pem" && block_type == "CERTIFICATE"
        ));
    }

    #[test]
    fn validate_signing_certificate_missing_digital_signature() {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        use openssl::x509::{X509Name, X509};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "KU Leaf")
            .unwrap();
        let subject = name.build();
        builder.set_subject_name(&subject).unwrap();
        builder.set_issuer_name(&subject).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        builder
            .append_extension(KeyUsage::new().key_cert_sign().build().unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        let err = validate_signing_certificate(&cert).unwrap_err();
        assert!(matches!(
            err,
            CorimError::X5chain(X5chainError::SigningCertLacksDigitalSignature)
        ));
    }

    #[test]
    fn validate_signing_certificate_absent_key_usage_passes() {
        use crl_helpers::{make_ca, make_leaf_zero_key_usage};

        let (ca, ca_key) = make_ca();
        let leaf = make_leaf_zero_key_usage(&ca, &ca_key);
        validate_signing_certificate(&leaf).unwrap();
    }

    fn test_rsa_leaf_end_entity() -> X509 {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        use openssl::x509::{X509Name, X509};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "RSA Leaf")
            .unwrap();
        let subject = name.build();
        builder.set_subject_name(&subject).unwrap();
        builder.set_issuer_name(&subject).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        builder
            .append_extension(KeyUsage::new().digital_signature().build().unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    fn test_ec_leaf_bad_key_usage() -> X509 {
        use openssl::asn1::Asn1Time;
        use openssl::ec::EcKey;
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        use openssl::x509::{X509Name, X509};

        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let ec_key = EcKey::private_key_from_pem(&signer_pem).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Bad KU EC Leaf")
            .unwrap();
        let subject = name.build();
        builder.set_subject_name(&subject).unwrap();
        builder.set_issuer_name(&subject).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        builder
            .append_extension(KeyUsage::new().key_cert_sign().build().unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    #[test]
    fn signed_corim_verify_with_x5chain_rejects_leaf_bad_key_usage() {
        let leaf = test_ec_leaf_bad_key_usage();
        validate_signing_certificate(&leaf).unwrap_err();

        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let cbor = build_signed_corim_with_chain(&leaf.to_der().unwrap(), &[], &signer_pem);
        let signed = signed_from_cbor(&cbor);
        let anchors = TrustAnchors::with_anchors(vec![leaf.clone()]);
        let err = signed.verify_with_x5chain(&anchors).unwrap_err();
        assert!(matches!(
            err,
            CorimError::X5chain(X5chainError::SigningCertLacksDigitalSignature)
        ));
    }

    #[test]
    fn signed_corim_verify_with_x5chain_rejects_rsa_leaf_key_type() {
        let rsa_leaf = test_rsa_leaf_end_entity();
        validate_signing_certificate(&rsa_leaf).unwrap();

        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let cbor = build_signed_corim_with_chain(&rsa_leaf.to_der().unwrap(), &[], &signer_pem);
        let signed = signed_from_cbor(&cbor);
        let anchors = TrustAnchors::with_anchors(vec![rsa_leaf]);
        let err = signed.verify_with_x5chain(&anchors).unwrap_err();
        assert!(
            matches!(
                err,
                CorimError::X5chain(X5chainError::UnsupportedKeyType(_))
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_empty_array() {
        let x5chain = OneOrMore::More(vec![]);
        let err = x5chain_flat_certificate_ders(&x5chain).unwrap_err();
        assert_custom_error_contains(err, "empty x5chain array");
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_invalid_leaf_der() {
        let x5chain = OneOrMore::One(Bytes::from(b"not-a-certificate".to_vec()));
        let err = x5chain_flat_certificate_ders(&x5chain).unwrap_err();
        assert_custom_error_contains(err, "invalid signing certificate");
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_invalid_concatenated_intermediate() {
        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let x5chain = OneOrMore::More(vec![leaf_der.into(), Bytes::from(vec![0x30, 0x82])]);
        let err = x5chain_flat_certificate_ders(&x5chain).unwrap_err();
        assert!(
            matches!(
                err,
                CorimError::Custom(ref message)
                    if message.contains("invalid intermediate certificates")
                        || message.contains("TLV length exceeds remaining input")
                        || message.contains("invalid long-form length")
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_oversized_signing_cert() {
        let oversized = vec![0u8; 256 * 1024 + 1];
        let x5chain = OneOrMore::One(oversized.into());
        let err = x5chain_flat_certificate_ders(&x5chain).unwrap_err();
        assert_custom_error_contains(err, "signing certificate exceeds 262144 byte limit");
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_oversized_intermediate_total() {
        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let first = vec![0x30u8; 200 * 1024];
        let second = vec![0x30u8; 100 * 1024];
        let x5chain = OneOrMore::More(vec![leaf_der.into(), first.into(), second.into()]);
        let err = x5chain_flat_certificate_ders(&x5chain).unwrap_err();
        assert_custom_error_contains(
            err,
            &format!("exceeds {X5CHAIN_MAX_INTERMEDIATE_TOTAL_BYTES} byte limit"),
        );
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_oversized_intermediate_element() {
        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let oversized = vec![0u8; X5CHAIN_MAX_CERT_DER_BYTES + 1];
        let x5chain = OneOrMore::More(vec![leaf_der.into(), oversized.into()]);
        let err = x5chain_flat_certificate_ders(&x5chain).unwrap_err();
        assert_custom_error_contains(
            err,
            &format!("intermediate COSE element exceeds {X5CHAIN_MAX_CERT_DER_BYTES} byte limit"),
        );
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_too_many_certs_in_chain() {
        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let int_der = chain_ders(&["int.cert.pem"])[0].clone();
        let concatenated: Vec<u8> = std::iter::repeat_n(int_der, 17).flatten().collect();
        let x5chain = OneOrMore::More(vec![leaf_der.into(), concatenated.into()]);
        let err = x5chain_flat_certificate_ders(&x5chain).unwrap_err();
        assert_custom_error_contains(
            err,
            &format!("certificate count exceeds {X5CHAIN_MAX_CHAIN_CERTS} limit"),
        );
    }

    #[test]
    fn x5chain_flat_certificate_ders_rejects_too_many_intermediate_elements() {
        let leaf_der = chain_ders(&["leaf.cert.pem"])[0].clone();
        let int_der = chain_ders(&["int.cert.pem"])[0].clone();
        let mut elements = vec![leaf_der.into()];
        for _ in 0..=X5CHAIN_MAX_INTERMEDIATE_COSE_ELEMENTS {
            elements.push(int_der.clone().into());
        }
        let err = x5chain_flat_certificate_ders(&OneOrMore::More(elements)).unwrap_err();
        assert_custom_error_contains(
            err,
            &format!(
                "intermediate COSE elements exceed {X5CHAIN_MAX_INTERMEDIATE_COSE_ELEMENTS} limit"
            ),
        );
    }

    #[test]
    fn trust_anchors_from_der_anchors_and_crls_rejects_bad_anchor_der() {
        let err =
            match TrustAnchors::from_der_anchors_and_crls(vec![b"not-a-cert".to_vec()], vec![]) {
                Err(err) => err,
                Ok(_) => panic!("expected bad anchor DER error"),
            };
        assert_custom_error_contains(err, "parsing trust anchor certificate");
    }

    #[test]
    fn trust_anchors_from_der_anchors_and_crls_rejects_bad_crl_der() {
        let root_der = chain_ders(&["root.cert.pem"])[0].clone();
        let err = match TrustAnchors::from_der_anchors_and_crls(
            vec![root_der],
            vec![b"not-a-crl".to_vec()],
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected bad CRL DER error"),
        };
        assert_custom_error_contains(err, "parsing CRL");
    }

    #[test]
    fn signed_corim_verify_with_x5chain_leaf_only_chain() {
        use crl_helpers::{make_ca, make_leaf};

        let (ca, ca_key) = make_ca();
        let (leaf, leaf_key) = make_leaf(&ca, &ca_key);
        let leaf_pem = leaf_key.serialize_pem();
        let cbor = build_signed_corim_with_chain(&leaf.to_der().unwrap(), &[], leaf_pem.as_bytes());
        let signed = signed_from_cbor(&cbor);
        let anchors = TrustAnchors::with_anchors(vec![ca.clone()]);
        signed.verify_with_x5chain(&anchors).unwrap();
    }

    #[test]
    fn parse_concatenated_certificate_ders_rejects_malformed_tlv_length() {
        let err = parse_concatenated_certificate_ders(&[0x30, 0x82, 0x01, 0x00]).unwrap_err();
        assert_custom_error_contains(err, "invalid intermediate certificates");
    }
}
