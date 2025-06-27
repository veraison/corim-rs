use crate::{
    CorimError, CoseAlgorithm, CoseEllipticCurve, CoseKey, CoseKeyOwner, CoseKty, CoseSigner,
    CoseVerifier,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::{Signer, Verifier},
};

/// A limitted implementation of a COSE signer using openssl crate that support EC2 keys, and
/// enforces the recommendations in the COSE spec, i.e. ES256 w/ prime256v1, ES384 w/ secp384r1,
/// and ES512 w/ secp521r1.
pub struct OpensslSigner {
    key: CoseKey,
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

        let key_bytes;
        let key_number;
        let group;
        match self.key.kty {
            CoseKty::Ec2 => {
                if self.key.d.is_none() {
                    return Err(CorimError::custom("key missing private component d"));
                }

                key_bytes = self.key.d.as_ref().unwrap();
                key_number = BigNum::from_slice(key_bytes).map_err(CorimError::custom)?;
                group = match self
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
                }
            }
            other => return Err(CorimError::Custom(format!("unsupported key type {other}"))),
        }

        let ec_key =
            EcKey::from_private_components(&group, &key_number, &EcPoint::new(&group).unwrap())?;
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

        let size;
        let group;
        let mut pub_key_bytes;
        match self.key.kty {
            CoseKty::Ec2 => {
                if self.key.y.is_none() {
                    return Err(CorimError::custom("key missing public component x"));
                }

                let mut x = self.key.x.as_ref().unwrap().to_vec();
                size = x.len();

                if self.key.y.is_some() && self.key.y.as_ref().unwrap().len() > 0 {
                    let mut y = self.key.y.as_ref().unwrap().to_vec();
                    pub_key_bytes = vec![4]; // SEC1 EC2 no point compression
                    pub_key_bytes.append(&mut x);
                    pub_key_bytes.append(&mut y);
                } else {
                    pub_key_bytes = vec![3]; // SEC1 EC2 w/ point compression
                    pub_key_bytes.append(&mut x);
                }

                group = match self
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
                }
            }
            other => return Err(CorimError::Custom(format!("unsupported key type {other}"))),
        }

        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, &pub_key_bytes, &mut ctx)?;
        let ec_key = EcKey::from_public_key(&group, &point)?;
        let verif_key = PKey::from_ec_key(ec_key)?;

        let mut verifier = Verifier::new(message_digest, &verif_key)?;
        verifier.update(&data)?;

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
}
