use const_oid::{db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1}, ObjectIdentifier};
use rsa::pkcs1::DecodeRsaPrivateKey;
use spki::{AlgorithmIdentifier, EncodePublicKey, SubjectPublicKeyInfoOwned};
use ssh_key::authorized_keys::Entry as KeyEntry;

use crate::Error;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Key {
    spki: SubjectPublicKeyInfoOwned,
}

impl Key {
    pub fn fingerprint(&self) -> String {
        hex::encode(self.spki.fingerprint_bytes().unwrap())
    }

    pub fn maybe_from_line(l: impl AsRef<str>) -> Option<Self> {
        let key_part = if let Some((chunk, _)) = l.as_ref().split_once('#') {
            chunk
        } else {
            l.as_ref()
        };

        key_part.parse::<KeyEntry>().map(|k| k.public_key().try_into().ok()).ok()?
    }
}

fn alg_check(spki: SubjectPublicKeyInfoOwned) -> Result<SubjectPublicKeyInfoOwned, Error> {
    if spki.algorithm.oid == RSA_ENCRYPTION || spki.algorithm.oid == ID_EC_PUBLIC_KEY {
        return Ok(spki)
    } else {
        return Err(Error::UnsupportedAlgorithm(spki.algorithm.oid.to_string()))
    }
}

impl TryFrom<x509_cert::certificate::CertificateInner> for Key {
    type Error = Error;

    fn try_from(cert: x509_cert::certificate::CertificateInner) -> Result<Self, Self::Error> {
        Ok(Self { spki: alg_check(cert.tbs_certificate.subject_public_key_info)? })
    }
}

impl TryFrom<x509_cert::request::CertReq> for Key {
    type Error = Error;

    fn try_from(csr: x509_cert::request::CertReq) -> Result<Self, Self::Error> {
        Ok(Self { spki: alg_check(csr.info.public_key)? })
    }
}

impl TryFrom<&rsa::RsaPrivateKey> for Key {
    type Error = Error;

    fn try_from(key: &rsa::RsaPrivateKey) -> Result<Self, Self::Error> {
        Ok(Self {
            spki: key
                .to_public_key()
                .to_public_key_der()?
                .decode_msg::<SubjectPublicKeyInfoOwned>()?
        })
    }
}

impl TryFrom<&ssh_key::private::PrivateKey> for Key {
    type Error = Error;

    fn try_from(key: &ssh_key::private::PrivateKey) -> Result<Self, Self::Error> {
        (&ssh_key::public::KeyData::from(key)).try_into()
    }
}

impl TryFrom<&ssh_key::public::PublicKey> for Key {
    type Error = Error;

    fn try_from(key: &ssh_key::public::PublicKey) -> Result<Self, Self::Error> {
        key.key_data().try_into()
    }
}

impl TryFrom<&ssh_key::public::KeyData> for Key {
    type Error = Error;

    fn try_from(key: &ssh_key::public::KeyData) -> Result<Self, Self::Error> {
        match key {
            ssh_key::public::KeyData::Rsa(k) => k.try_into(),
            ssh_key::public::KeyData::Ecdsa(k) => k.try_into(),
            ssh_key::public::KeyData::SkEcdsaSha2NistP256(k) => k.try_into(),
            ssh_key::public::KeyData::Ed25519(k) => k.try_into(),
            ssh_key::public::KeyData::SkEd25519(k) => k.public_key().try_into(),
            _ => Err(Error::UnsupportedAlgorithm(key.algorithm().to_string())),
        }
    }
}

impl TryFrom<&ssh_key::public::RsaPublicKey> for Key {
    type Error = Error;

    fn try_from(key: &ssh_key::public::RsaPublicKey) -> Result<Self, Self::Error> {
        Ok(Self { spki: rsa::RsaPublicKey::try_from(key)?.to_public_key_der()?.decode_msg()? })
    }
}

impl TryFrom<&ssh_key::public::EcdsaPublicKey> for Key {
    type Error = Error;

    fn try_from(key: &ssh_key::public::EcdsaPublicKey) -> Result<Self, Self::Error> {
        let spki = match key {
            ssh_key::public::EcdsaPublicKey::NistP256(point) => p256::PublicKey::from_sec1_bytes(point.as_bytes())?.to_public_key_der(),
            ssh_key::public::EcdsaPublicKey::NistP384(point) => p384::PublicKey::from_sec1_bytes(point.as_bytes())?.to_public_key_der(),
            ssh_key::public::EcdsaPublicKey::NistP521(point) => p521::PublicKey::from_sec1_bytes(point.as_bytes())?.to_public_key_der(),
        }?.decode_msg()?;
        Ok(Self { spki })
    }
}

impl TryFrom<&ssh_key::public::SkEcdsaSha2NistP256> for Key {
    type Error = Error;

    fn try_from(key: &ssh_key::public::SkEcdsaSha2NistP256) -> Result<Self, Self::Error> {
        Ok(Self { spki: p256::PublicKey::from_sec1_bytes(key.ec_point().as_bytes())?.to_public_key_der()?.decode_msg()? })
    }
}

impl TryFrom<&ssh_key::public::Ed25519PublicKey> for Key {
    type Error = Error;

    fn try_from(key: &ssh_key::public::Ed25519PublicKey) -> Result<Self, Self::Error> {
        Ok(Self { spki: ed25519::pkcs8::PublicKeyBytes(key.0).to_public_key_der()?.decode_msg()? })
    }
}

impl TryFrom<pkcs8::PrivateKeyInfo<'_>> for Key {
    type Error = Error;

    fn try_from(pki: pkcs8::PrivateKeyInfo<'_>) -> Result<Self, Self::Error>
    {
        let spki = match pki {
            // RSA
            pkcs8::PrivateKeyInfo { algorithm: AlgorithmIdentifier { oid: pkcs1::ALGORITHM_OID, .. }, private_key: der, .. } =>
                rsa::RsaPrivateKey::from_pkcs1_der(der)?
                    .to_public_key()
                    .to_public_key_der()?
                    .decode_msg::<SubjectPublicKeyInfoOwned>()?,
            // ECDSA
            pkcs8::PrivateKeyInfo { algorithm: AlgorithmIdentifier { oid: elliptic_curve::ALGORITHM_OID, parameters: Some(params) }, .. } => {
                let curve: ObjectIdentifier = params.try_into()?;

                match curve {
                    SECP_256_R_1 => <pkcs8::PrivateKeyInfo<'_> as TryInto<p256::SecretKey>>::try_into(pki)?
                        .public_key()
                        .to_public_key_der(),
                    SECP_384_R_1 => <pkcs8::PrivateKeyInfo<'_> as TryInto<p384::SecretKey>>::try_into(pki)?
                        .public_key()
                        .to_public_key_der(),
                    SECP_521_R_1 => <pkcs8::PrivateKeyInfo<'_> as TryInto<p521::SecretKey>>::try_into(pki)?
                        .public_key()
                        .to_public_key_der(),
                    _ => Err(Error::unsupported_curve(curve.to_string()))?,
                }?
                .decode_msg::<SubjectPublicKeyInfoOwned>()?
            },
            _ => Err(Error::unsupported_algorithm(pki.algorithm.oid.to_string()))?,
        };

        Ok(Self { spki })
    }
}
