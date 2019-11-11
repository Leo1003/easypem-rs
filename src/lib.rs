extern crate pest;
#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate lazy_static;

use std::fmt::{Display, Error as FmtError, Formatter, Result as FmtResult};
use std::str::FromStr;

mod builder;
pub mod error;
pub mod headers;
mod parser;

/// Represent a PEM data
///
/// ```
/// # use easypem::{PemMessage, headers::PemHeader};
///
/// let pem = PemMessage {
///     label: "MESSAGE".to_owned(),
///     headers: PemHeader::default(),
///     content: b"This is a message".to_vec(),
/// };
///
/// println!("{}", &pem);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PemMessage {
    pub label: String,
    pub headers: headers::PemHeader,
    pub content: Vec<u8>,
}

impl Display for PemMessage {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if self.label.is_empty() {
            return Err(FmtError);
        }
        writeln!(f, "-----BEGIN {}-----", &self.label)?;
        write!(f, "{}", &self.headers)?;
        if !self.headers.is_empty() {
            writeln!(f)?;
        }
        base64::encode(&self.content)
            .as_bytes()
            .chunks(64)
            .map(|v| std::str::from_utf8(v).unwrap())
            .map(|s| writeln!(f, "{}", s))
            .collect::<FmtResult>()?;
        write!(f, "-----END {}-----", &self.label)
    }
}

impl FromStr for PemMessage {
    type Err = error::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parser::pem_parser(s)
    }
}

/// Label for Certificate
pub const CERTIFICATE_LABEL: &str = "CERTIFICATE";
/// Label for X509 Certificate Revocation List
pub const CRL_LABEL: &str = "X509 CRL";
/// Label for Certification Request
pub const CERTREQ_LABEL: &str = "CERTIFICATE REQUEST";
/// Label for PKCS #7 Cryptographic Message
pub const PKCS7_LABEL: &str = "PKCS7";
/// Label for Cryptographic Message Syntax
pub const CMS_LABEL: &str = "CMS";
/// Label for PKCS #8 Private Key
pub const PRIVKEY_LABEL: &str = "PRIVATE KEY";
/// Label for PKCS #8 Encrypted Private Key
pub const ENC_PRIVKEY_LABEL: &str = "ENCRYPTED PRIVATE KEY";
/// Label for Attribute Certificates
pub const ATTRCERT_LABEL: &str = "ATTRIBUTE CERTIFICATE";
/// Label for Public Key
pub const PUBKEY_LABEL: &str = "PUBLIC KEY";
