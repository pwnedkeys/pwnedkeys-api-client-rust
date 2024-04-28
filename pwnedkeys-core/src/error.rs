use std::backtrace::Backtrace;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("could not convert elliptic curve key: {0}")]
    EcConversionFailure(#[from] elliptic_curve::Error),

    #[error("could not convert PKCS#1 key: {0}")]
    Pkcs1ConversionFailure(#[from] pkcs1::Error),

    #[error("could not decode DER: {0}")]
    Pkcs8ConversionFailure(#[from] pkcs8::Error),

    #[error("could not convert PKCS#8 key: {0}")]
    Pkcs8DecodingFailure(#[from] pkcs8::der::Error),

    #[error("could not convert to SPKI: {0}")]
    SpkiConversionFailure(#[from] spki::Error),

    #[error("could not convert SSH key: {0}")]
    SshConversionFailure(#[from] ssh_key::Error),

    #[error("unsupported elliptic curve {0}")]
    UnsupportedCurve(String),

    #[error("unsupported key algorithm {0}")]
    UnsupportedAlgorithm(String),

}

impl Error {
    pub fn unsupported_curve(name: impl Into<String>) -> Self {
        Error::UnsupportedCurve(name.into())
    }

    pub fn unsupported_algorithm(name: impl Into<String>) -> Self {
        Error::UnsupportedAlgorithm(name.into())
    }
}
