use const_oid::{db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1}, ObjectIdentifier};
use rsa::pkcs1::DecodeRsaPrivateKey;
use spki::{AlgorithmIdentifier, EncodePublicKey, SubjectPublicKeyInfoOwned};

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Key {
    spki: SubjectPublicKeyInfoOwned,
}

impl Key {
    pub fn fingerprint(&self) -> String {
        hex::encode(self.spki.fingerprint_bytes().unwrap())
    }
}

fn alg_check(spki: SubjectPublicKeyInfoOwned) -> Result<SubjectPublicKeyInfoOwned, String> {
    if spki.algorithm.oid == RSA_ENCRYPTION || spki.algorithm.oid == ID_EC_PUBLIC_KEY {
        return Ok(spki)
    } else {
        return Err("unsupported key algorithm".to_string())
    }
}

impl TryFrom<x509_cert::certificate::CertificateInner> for Key {
    type Error = String;

    fn try_from(cert: x509_cert::certificate::CertificateInner) -> Result<Self, Self::Error> {
        Ok(Self { spki: alg_check(cert.tbs_certificate.subject_public_key_info)? })
    }
}

impl TryFrom<x509_cert::request::CertReq> for Key {
    type Error = String;

    fn try_from(csr: x509_cert::request::CertReq) -> Result<Self, Self::Error> {
        Ok(Self { spki: alg_check(csr.info.public_key)? })
    }
}

impl TryFrom<&rsa::RsaPrivateKey> for Key {
    type Error = String;

    fn try_from(key: &rsa::RsaPrivateKey) -> Result<Self, Self::Error> {
        Ok(Self {
            spki: key
                .to_public_key()
                .to_public_key_der()
                .map_err(|e| format!("could not decode PKCS#1: {e}"))?
                .decode_msg::<SubjectPublicKeyInfoOwned>()
                .map_err(|e| format!("could not decode PKCS#1: {e}"))?
        })
    }
}

impl TryFrom<&ssh_key::private::PrivateKey> for Key {
    type Error = String;

    fn try_from(key: &ssh_key::private::PrivateKey) -> Result<Self, Self::Error> {
        (&ssh_key::public::KeyData::from(key)).try_into()
    }
}

impl TryFrom<&ssh_key::public::PublicKey> for Key {
    type Error = String;

    fn try_from(key: &ssh_key::public::PublicKey) -> Result<Self, Self::Error> {
        key.key_data().try_into()
    }
}

impl TryFrom<&ssh_key::public::KeyData> for Key {
    type Error = String;

    fn try_from(key: &ssh_key::public::KeyData) -> Result<Self, Self::Error> {
        match key {
            ssh_key::public::KeyData::Rsa(k) => k.try_into(),
            ssh_key::public::KeyData::Ecdsa(k) => k.try_into(),
            _ => Err(format!("unsupported SSH key algorithm: {}", key.algorithm())),
        }
    }
}

fn cnds<E>(e: E) -> String where E: std::fmt::Display {
    format!("could not decode SSH key: {e}")
}

impl TryFrom<&ssh_key::public::RsaPublicKey> for Key {
    type Error = String;

    fn try_from(key: &ssh_key::public::RsaPublicKey) -> Result<Self, Self::Error> {
        Ok(Self { spki: rsa::RsaPublicKey::try_from(key).map_err(cnds)?.to_public_key_der().map_err(cnds)?.decode_msg().map_err(cnds)? })
    }
}

impl TryFrom<&ssh_key::public::EcdsaPublicKey> for Key {
    type Error = String;

    fn try_from(key: &ssh_key::public::EcdsaPublicKey) -> Result<Self, Self::Error> {
        let spki = match key {
            ssh_key::public::EcdsaPublicKey::NistP256(point) => p256::PublicKey::from_sec1_bytes(point.as_bytes()).map_err(cnds)?.to_public_key_der().map_err(cnds),
            ssh_key::public::EcdsaPublicKey::NistP384(point) => p384::PublicKey::from_sec1_bytes(point.as_bytes()).map_err(cnds)?.to_public_key_der().map_err(cnds),
            ssh_key::public::EcdsaPublicKey::NistP521(point) => p521::PublicKey::from_sec1_bytes(point.as_bytes()).map_err(cnds)?.to_public_key_der().map_err(cnds),
        }?.decode_msg().map_err(cnds)?;
        Ok(Self { spki })
    }
}

fn cnd8<E>(e: E) -> String where E: std::fmt::Display {
    format!("could not decode PKCS#8: {e}")
}

impl TryFrom<pkcs8::PrivateKeyInfo<'_>> for Key {
    type Error = String;

    fn try_from(pki: pkcs8::PrivateKeyInfo<'_>) -> Result<Self, Self::Error>
    {
        let spki = match pki {
            // RSA
            pkcs8::PrivateKeyInfo { algorithm: AlgorithmIdentifier { oid: pkcs1::ALGORITHM_OID, .. }, private_key: der, .. } =>
                rsa::RsaPrivateKey::from_pkcs1_der(der)
                    .map_err(cnd8)?
                    .to_public_key()
                    .to_public_key_der()
                    .map_err(cnd8)?
                    .decode_msg::<SubjectPublicKeyInfoOwned>()
                    .map_err(cnd8)?,
            // ECDSA
            pkcs8::PrivateKeyInfo { algorithm: AlgorithmIdentifier { oid: elliptic_curve::ALGORITHM_OID, parameters: Some(params) }, .. } => {
                let curve: ObjectIdentifier = params.try_into().map_err(cnd8)?;

                match curve {
                    SECP_256_R_1 => <pkcs8::PrivateKeyInfo<'_> as TryInto<p256::SecretKey>>::try_into(pki)
                        .map_err(cnd8)?
                        .public_key()
                        .to_public_key_der(),
                    SECP_384_R_1 => <pkcs8::PrivateKeyInfo<'_> as TryInto<p384::SecretKey>>::try_into(pki)
                        .map_err(cnd8)?
                        .public_key()
                        .to_public_key_der(),
                    SECP_521_R_1 => <pkcs8::PrivateKeyInfo<'_> as TryInto<p521::SecretKey>>::try_into(pki)
                        .map_err(cnd8)?
                        .public_key()
                        .to_public_key_der(),
                    _ => Err("unsupported curve in PrivateKeyInfo")?,
                }
                .map_err(cnd8)?
                .decode_msg::<SubjectPublicKeyInfoOwned>()
                .map_err(cnd8)?
            },
            _ => Err("unsupported key algorithm in PrivateKeyInfo")?,
        };

        Ok(Self { spki })
    }
}
