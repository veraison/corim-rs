use crate::{
    CorimError, CoseAlgorithm, CoseEllipticCurve, CoseKey, CoseKeyOwner, CoseKty, CoseSigner,
    CoseVerifier, X5chainError,
};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::{Signer, Verifier},
    x509::{X509Crl, X509CrlRef, X509Ref, X509},
};
use openssl_sys as ffi;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::os::raw::c_long;
use x509_parser::pem::Pem;
use x509_parser::prelude::*;

/// A limited implementation of a COSE signer using openssl crate that support EC2 keys, and
/// enforces the recommendations in the COSE spec, i.e. ES256 w/ prime256v1, ES384 w/ secp384r1,
/// and ES512 w/ secp521r1.
pub struct OpensslSigner {
    key: CoseKey,
}

fn x509_ec_coordinate_len(crv: &CoseEllipticCurve) -> Result<i32, CorimError> {
    match crv {
        CoseEllipticCurve::P256 => Ok(32),
        CoseEllipticCurve::P384 => Ok(48),
        CoseEllipticCurve::P521 => Ok(66),
        other => Err(CorimError::X5chain(X5chainError::UnsupportedKeyType(
            format!("unsupported EC curve {other}"),
        ))),
    }
}

impl OpensslSigner {
    pub fn private_key_from_pem(bytes: &[u8]) -> Result<Self, CorimError> {
        let ec_key = EcKey::private_key_from_pem(bytes)?;

        let crv = match ec_key.group().curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Ok(CoseEllipticCurve::P256),
            Some(Nid::SECP384R1) => Ok(CoseEllipticCurve::P384),
            Some(Nid::SECP521R1) => Ok(CoseEllipticCurve::P521),
            Some(other) => Err(CorimError::Custom(format!(
                "unsupported EC curve {}",
                other.short_name()?
            ))),
            None => Err(CorimError::custom("could not get EC curve from key")),
        }?;

        Ok(Self {
            key: CoseKey {
                kty: CoseKty::Ec2,
                alg: None,
                crv: Some(crv),
                x: None,
                y: None,
                d: Some(ec_key.private_key().to_vec().into()),
                key_ops: None,
                base_iv: None,
                k: None,
                kid: None,
            },
        })
    }

    pub fn public_key_from_pem(bytes: &[u8]) -> Result<Self, CorimError> {
        let ec_key = EcKey::public_key_from_pem(bytes)?;
        let group = ec_key.group();

        let crv = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Ok(CoseEllipticCurve::P256),
            Some(Nid::SECP384R1) => Ok(CoseEllipticCurve::P384),
            Some(Nid::SECP521R1) => Ok(CoseEllipticCurve::P521),
            Some(other) => Err(CorimError::Custom(format!(
                "unsupported EC curve {}",
                other.short_name()?
            ))),
            None => Err(CorimError::custom("could not get EC curve from key")),
        }?;

        let ec_point = ec_key.public_key();

        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        ec_point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        Ok(Self {
            key: CoseKey {
                kty: CoseKty::Ec2,
                alg: None,
                crv: Some(crv),
                x: Some(x.to_vec().into()),
                y: Some(y.to_vec().into()),
                d: None,
                key_ops: None,
                base_iv: None,
                k: None,
                kid: None,
            },
        })
    }

    /// Build a verifier from the public key in an X.509 certificate.
    pub(crate) fn public_key_from_x509(cert: &X509Ref) -> Result<Self, CorimError> {
        let pkey = cert.public_key()?;
        let ec_key = pkey.ec_key().map_err(|_| {
            CorimError::X5chain(X5chainError::UnsupportedKeyType("not an EC2 key".into()))
        })?;
        let group = ec_key.group();

        let crv = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Ok(CoseEllipticCurve::P256),
            Some(Nid::SECP384R1) => Ok(CoseEllipticCurve::P384),
            Some(Nid::SECP521R1) => Ok(CoseEllipticCurve::P521),
            Some(other) => Err(CorimError::X5chain(X5chainError::UnsupportedKeyType(
                format!("unsupported EC curve {}", other.short_name()?),
            ))),
            None => Err(CorimError::X5chain(X5chainError::UnsupportedKeyType(
                "could not get EC curve from key".into(),
            ))),
        }?;
        let coordinate_len = x509_ec_coordinate_len(&crv)?;

        let ec_point = ec_key.public_key();

        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        ec_point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        Ok(Self {
            key: CoseKey {
                kty: CoseKty::Ec2,
                alg: None,
                crv: Some(crv),
                x: Some(x.to_vec_padded(coordinate_len)?.into()),
                y: Some(y.to_vec_padded(coordinate_len)?.into()),
                d: None,
                key_ops: None,
                base_iv: None,
                k: None,
                kid: None,
            },
        })
    }
}

impl From<CoseKey> for OpensslSigner {
    fn from(key: CoseKey) -> Self {
        Self { key }
    }
}

impl CoseKeyOwner for OpensslSigner {
    fn to_cose_key(&self) -> CoseKey {
        self.key.clone()
    }
}

impl From<openssl::error::ErrorStack> for CorimError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        CorimError::custom(value.to_string())
    }
}

impl CoseSigner for OpensslSigner {
    fn sign(&self, alg: CoseAlgorithm, data: &[u8]) -> Result<Vec<u8>, CorimError> {
        let message_digest = match alg {
            CoseAlgorithm::ES256 => MessageDigest::sha256(),
            CoseAlgorithm::ES384 => MessageDigest::sha384(),
            CoseAlgorithm::ES512 => MessageDigest::sha512(),
            other => {
                return Err(CorimError::Custom(format!(
                    "unexpected COSE algorithm {other}"
                )))
            }
        };

        let (key_bytes, key_number, group) = match self.key.kty {
            CoseKty::Ec2 => {
                let key_bytes = self
                    .key
                    .d
                    .as_ref()
                    .ok_or_else(|| CorimError::custom("key missing private component d"))?;
                let key_number = BigNum::from_slice(key_bytes).map_err(CorimError::custom)?;
                let group = match self
                    .key
                    .crv
                    .as_ref()
                    .ok_or(CorimError::unset_mandatory_field("CoseKey", "crv"))?
                {
                    CoseEllipticCurve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
                    CoseEllipticCurve::P384 => EcGroup::from_curve_name(Nid::SECP384R1)?,
                    CoseEllipticCurve::P521 => EcGroup::from_curve_name(Nid::SECP521R1)?,
                    other => {
                        return Err(CorimError::InvalidFieldValue(
                            "CoseKey".to_string(),
                            "crv".to_string(),
                            other.to_string(),
                        ));
                    }
                };
                (key_bytes, key_number, group)
            }
            other => return Err(CorimError::Custom(format!("unsupported key type {other}"))),
        };

        let point = EcPoint::new(&group)?;
        let ec_key = EcKey::from_private_components(&group, &key_number, &point)?;
        let final_key = PKey::from_ec_key(ec_key)?;

        let mut signer = Signer::new(message_digest, &final_key)?;
        signer.update(data)?;

        let der_sig = signer.sign_to_vec()?;
        let priv_comp = EcdsaSig::from_der(&der_sig)?;

        let size: i32 = key_bytes.len() as i32;
        let mut s = priv_comp.r().to_vec_padded(size)?;
        s.append(&mut priv_comp.s().to_vec_padded(size)?);
        Ok(s)
    }
}

impl CoseVerifier for OpensslSigner {
    fn verify_signature(
        &self,
        alg: CoseAlgorithm,
        sig: &[u8],
        data: &[u8],
    ) -> Result<(), CorimError> {
        let message_digest = match alg {
            CoseAlgorithm::ES256 => MessageDigest::sha256(),
            CoseAlgorithm::ES384 => MessageDigest::sha384(),
            CoseAlgorithm::ES512 => MessageDigest::sha512(),
            other => {
                return Err(CorimError::Custom(format!(
                    "unexpected COSE algorithm {other}"
                )))
            }
        };

        let (size, group, pub_key_bytes) = match self.key.kty {
            CoseKty::Ec2 => {
                let x = self
                    .key
                    .x
                    .as_ref()
                    .ok_or_else(|| CorimError::custom("key missing public component x"))?;
                let mut x = x.to_vec();
                let size = x.len();

                let pub_key_bytes = if self.key.y.as_ref().is_some_and(|y| !y.is_empty()) {
                    let mut y = self.key.y.as_ref().unwrap().to_vec();
                    let mut pub_key_bytes = vec![4]; // SEC1 EC2 no point compression
                    pub_key_bytes.append(&mut x);
                    pub_key_bytes.append(&mut y);
                    pub_key_bytes
                } else {
                    let mut pub_key_bytes = vec![3]; // SEC1 EC2 w/ point compression
                    pub_key_bytes.append(&mut x);
                    pub_key_bytes
                };

                let group = match self
                    .key
                    .crv
                    .as_ref()
                    .ok_or(CorimError::unset_mandatory_field("CoseKey", "crv"))?
                {
                    CoseEllipticCurve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
                    CoseEllipticCurve::P384 => EcGroup::from_curve_name(Nid::SECP384R1)?,
                    CoseEllipticCurve::P521 => EcGroup::from_curve_name(Nid::SECP521R1)?,
                    other => {
                        return Err(CorimError::InvalidFieldValue(
                            "CoseKey".to_string(),
                            "crv".to_string(),
                            other.to_string(),
                        ));
                    }
                };
                (size, group, pub_key_bytes)
            }
            other => return Err(CorimError::Custom(format!("unsupported key type {other}"))),
        };

        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, &pub_key_bytes, &mut ctx)?;
        let ec_key = EcKey::from_public_key(&group, &point)?;
        let verif_key = PKey::from_ec_key(ec_key)?;

        let mut verifier = Verifier::new(message_digest, &verif_key)?;
        verifier.update(data)?;

        let expected_len = size * 2;
        if sig.len() != expected_len {
            return Err(CorimError::InvalidSignature);
        }

        let ecdsa_sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&sig[..size])?,
            BigNum::from_slice(&sig[size..])?,
        )?;

        if verifier.verify(&ecdsa_sig.to_der()?)? {
            Ok(())
        } else {
            Err(CorimError::InvalidSignature)
        }
    }
}

fn certificate_is_ca(cert: &X509Ref) -> Result<bool, CorimError> {
    // SAFETY: `cert` is a valid `X509Ref`; `X509_get_extension_flags` only reads certificate
    // state. `EXFLAG_CA` is set by OpenSSL when basicConstraints has CA:TRUE; absent extension
    // leaves the flag clear (not a CA). Prefer this over manual `BASIC_CONSTRAINTS` FFI because
    // `openssl-sys` does not expose typed accessors for that struct.
    let flags = unsafe { ffi::X509_get_extension_flags(cert.as_ptr()) };
    Ok((flags & ffi::EXFLAG_CA) != 0)
}

/// Validates leaf signing-certificate policy before PKIX path validation.
pub(crate) fn validate_signing_certificate(cert: &X509Ref) -> Result<(), CorimError> {
    if certificate_is_ca(cert)? {
        return Err(CorimError::X5chain(X5chainError::SigningCertMustNotBeCa));
    }

    // OpenSSL returns `UINT32_MAX` from `X509_get_key_usage` when the KeyUsage extension is
    // absent (distinct from present-with-zero-bits).
    const X509_KU_ABSENT: u32 = 0xffff_ffff;

    // SAFETY: `cert` is a valid `X509Ref` for the call; `X509_get_key_usage` only reads
    // certificate state and does not retain pointers past the call.
    let ku = unsafe { ffi::X509_get_key_usage(cert.as_ptr()) };
    if ku != X509_KU_ABSENT && (ku & ffi::X509v3_KU_DIGITAL_SIGNATURE) == 0 {
        return Err(CorimError::X5chain(
            X5chainError::SigningCertLacksDigitalSignature,
        ));
    }

    Ok(())
}

pub(crate) fn cert_to_der(cert: &X509Ref) -> Result<Vec<u8>, CorimError> {
    cert.to_der()
        .map_err(|e| CorimError::custom(format!("encoding certificate: {e}")))
}

fn pem_parse_error(context: &str, err: impl std::fmt::Display) -> CorimError {
    CorimError::custom(format!("{context}: {err}"))
}

/// Iterate PEM blocks in `data` using [`x509_parser`].
pub(crate) fn for_each_pem_block(
    data: &[u8],
    mut f: impl FnMut(&str, &[u8]) -> Result<(), CorimError>,
) -> Result<(), CorimError> {
    for pem in Pem::iter_from_buffer(data.trim_ascii_start()) {
        let pem = pem.map_err(|e| pem_parse_error("reading PEM", e))?;
        f(&pem.label, &pem.contents)?;
    }
    Ok(())
}

/// Parse one or more concatenated X.509 certificates from DER (no padding between certs).
///
/// Uses [`x509_parser`] to locate each certificate boundary, then validates each slice
/// with OpenSSL [`certificate_from_der`].
pub(crate) fn parse_concatenated_certificate_ders(data: &[u8]) -> Result<Vec<Vec<u8>>, CorimError> {
    let mut rest = data;
    let mut ders = Vec::new();
    while !rest.is_empty() {
        let (remaining, _) = parse_x509_certificate(rest).map_err(|e| {
            CorimError::custom(format!(
                "decoding x5chain: invalid intermediate certificates: {e}"
            ))
        })?;
        let consumed = rest.len() - remaining.len();
        let der = rest[..consumed].to_vec();
        certificate_from_der(&der)?;
        ders.push(der);
        rest = remaining;
    }
    Ok(ders)
}

/// Parse one certificate from DER or a PEM `CERTIFICATE` block; returns canonical DER bytes.
///
/// PEM: first block label must be `CERTIFICATE` ([`x509_parser`]); contents parsed via
/// [`certificate_from_der`]. DER: exact-length OpenSSL `d2i_X509` (no trailing bytes).
pub(crate) fn certificate_der_from_pem_or_der(data: &[u8]) -> Result<Vec<u8>, CorimError> {
    let cert = certificate_from_pem_or_der(data)?;
    cert_to_der(&cert)
}

/// Parse one certificate from DER or the first PEM `CERTIFICATE` block.
pub(crate) fn certificate_from_pem_or_der(data: &[u8]) -> Result<X509, CorimError> {
    let data = data.trim_ascii_start();
    if data.starts_with(b"-----BEGIN") {
        let mut blocks = Pem::iter_from_buffer(data);
        let pem = blocks
            .next()
            .ok_or_else(|| CorimError::custom("reading PEM: no PEM blocks found"))?
            .map_err(|e| pem_parse_error("reading PEM", e))?;
        if pem.label != "CERTIFICATE" {
            return Err(CorimError::custom(format!(
                "reading PEM: expected CERTIFICATE block, got {}",
                pem.label
            )));
        }
        return certificate_from_der(&pem.contents);
    }
    certificate_from_der(data)
}

/// Parse one X.509 certificate from DER; rejects trailing bytes after the object.
pub(crate) fn certificate_from_der(der: &[u8]) -> Result<X509, CorimError> {
    let cert = parse_exact_x509_der(der, "certificate", |out, input, len| unsafe {
        ffi::d2i_X509(out, input, len)
    })?;
    Ok(cert)
}

/// Parse one X.509 CRL from DER; rejects trailing bytes after the object.
pub(crate) fn crl_from_der(der: &[u8]) -> Result<X509Crl, CorimError> {
    let crl = parse_exact_x509_der(der, "CRL", |out, input, len| unsafe {
        ffi::d2i_X509_CRL(out, input, len)
    })?;
    Ok(crl)
}

/// Parse one DER object with OpenSSL `d2i_*`; reject trailing bytes after the object.
fn parse_exact_x509_der<T, F>(der: &[u8], kind: &str, parse: F) -> Result<T, CorimError>
where
    F: FnOnce(*mut *mut T::CType, *mut *const u8, c_long) -> *mut T::CType,
    T: ForeignType,
{
    if der.len() > c_long::MAX as usize {
        return Err(CorimError::custom(format!(
            "parsing {kind}: DER input too large"
        )));
    }

    ffi::init();
    let start = der.as_ptr();
    let mut cursor = start;
    // SAFETY: OpenSSL d2i_* only reads `der.len()` bytes from `cursor` and advances it
    // to the first unconsumed byte. The returned owned pointer is wrapped immediately.
    let ptr = parse(std::ptr::null_mut(), &mut cursor, der.len() as c_long);
    if ptr.is_null() {
        let detail = ErrorStack::get().to_string();
        let detail = if detail.trim().is_empty() {
            "OpenSSL rejected DER input".to_string()
        } else {
            detail
        };
        return Err(CorimError::custom(format!("parsing {kind}: {detail}")));
    }
    // SAFETY: `ptr` is a non-null owned OpenSSL object returned by d2i_*.
    let parsed = unsafe { T::from_ptr(ptr) };
    // SAFETY: `cursor` was advanced within the same input allocation by OpenSSL.
    let consumed = unsafe { cursor.offset_from(start) };
    if consumed < 0 || consumed as usize != der.len() {
        return Err(CorimError::custom(format!(
            "parsing {kind}: trailing data after DER"
        )));
    }
    Ok(parsed)
}

/// Return `Ok(true)` when `crl` is signed by `issuer`.
///
/// Returns `Ok(false)` when issuer names differ (CRL ignored for that issuer).
/// Returns `Err` when names match but signature verification fails or OpenSSL errors.
pub(crate) fn crl_signed_by_issuer(crl: &X509CrlRef, issuer: &X509Ref) -> Result<bool, CorimError> {
    // Cheap name pre-filter using X509_NAME_cmp (the same normalized comparison
    // OpenSSL applies internally for CRL matching); avoids a signature verification
    // for CRLs whose issuer name does not match the candidate CA subject.
    if !matches!(
        crl.issuer_name().try_cmp(issuer.subject_name()),
        Ok(Ordering::Equal)
    ) {
        return Ok(false);
    }
    let issuer_key = issuer
        .public_key()
        .map_err(|e| CorimError::custom(format!("getting CRL issuer public key: {e}")))?;
    match crl
        .verify(&issuer_key)
        .map_err(|e| CorimError::custom(format!("verifying CRL signature: {e}")))?
    {
        true => Ok(true),
        false => Err(CorimError::custom(
            "verifying CRL signature: CRL signature invalid",
        )),
    }
}

/// Trust-anchor loader with DER deduplication cache.
pub(crate) struct AnchorLoader {
    certs: Vec<X509>,
    der_set: HashSet<Vec<u8>>,
}

impl AnchorLoader {
    pub(crate) fn new() -> Self {
        Self {
            certs: Vec::new(),
            der_set: HashSet::new(),
        }
    }

    pub(crate) fn push_deduped(&mut self, cert: X509) -> Result<(), CorimError> {
        let der = cert_to_der(&cert)?;
        if self.der_set.insert(der) {
            self.certs.push(cert);
        }
        Ok(())
    }

    pub(crate) fn into_certs(self) -> Vec<X509> {
        self.certs
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_openssl_ec_sign_verify() {
        let priv_pem = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGcXyKllYJ/Ll0jUI9LfK/7uokvFibisW5lM8DZaRO+toAoGCCqGSM49
AwEHoUQDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpoeCJsPxG2h
zMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END EC PRIVATE KEY-----
"#;
        let pub_pem = r#"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4Q
hU80ttXzJ7waTpoeCJsPxG2hzMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END PUBLIC KEY-----
"#;
        let message = "Hello, World!";

        let signer = OpensslSigner::private_key_from_pem(priv_pem.as_bytes()).unwrap();
        let sig = signer
            .sign(CoseAlgorithm::ES256, message.as_bytes())
            .unwrap();

        let verifier = OpensslSigner::public_key_from_pem(pub_pem.as_bytes()).unwrap();
        verifier
            .verify_signature(CoseAlgorithm::ES256, &sig, message.as_bytes())
            .unwrap();
    }

    #[test]
    fn verify_signature_rejects_short_ecdsa_sig() {
        let pub_pem = r#"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4Q
hU80ttXzJ7waTpoeCJsPxG2hzMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END PUBLIC KEY-----
"#;
        let verifier = OpensslSigner::public_key_from_pem(pub_pem.as_bytes()).unwrap();
        let err = verifier
            .verify_signature(CoseAlgorithm::ES256, &[0u8; 32], b"data")
            .unwrap_err();
        assert!(matches!(err, CorimError::InvalidSignature));
    }

    #[test]
    fn public_key_from_x509_pads_ec_coordinates() {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::x509::{X509Name, X509};

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        for _ in 0..512 {
            let ec_key = EcKey::generate(&group).unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            let mut x = BigNum::new().unwrap();
            let mut y = BigNum::new().unwrap();
            ec_key
                .public_key()
                .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
                .unwrap();
            if x.to_vec().len() == 32 && y.to_vec().len() == 32 {
                continue;
            }

            let pkey = PKey::from_ec_key(ec_key).unwrap();
            let mut builder = X509::builder().unwrap();
            builder.set_version(2).unwrap();
            let mut name = X509Name::builder().unwrap();
            name.append_entry_by_text("CN", "leading-zero EC").unwrap();
            let name = name.build();
            builder.set_subject_name(&name).unwrap();
            builder.set_issuer_name(&name).unwrap();
            builder.set_pubkey(&pkey).unwrap();
            builder
                .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            builder.sign(&pkey, MessageDigest::sha256()).unwrap();

            let verifier = OpensslSigner::public_key_from_x509(&builder.build()).unwrap();
            let cose_key = verifier.to_cose_key();
            assert_eq!(cose_key.x.as_ref().unwrap().len(), 32);
            assert_eq!(cose_key.y.as_ref().unwrap().len(), 32);
            return;
        }

        panic!("did not generate an EC key with a leading-zero coordinate");
    }
}
