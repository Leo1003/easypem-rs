extern crate pest;
#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate lazy_static;

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

mod builder;
pub mod error;
pub mod headers;
mod parser;

#[derive(Debug)]
pub struct PemMessage {
    pub label: String,
    pub headers: headers::PemHeader,
    pub content: Vec<u8>,
}

impl Display for PemMessage {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
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

pub const CERTIFICATE_LABEL: &str = "CERTIFICATE";
pub const CRL_LABEL: &str = "X509 CRL";
pub const CERTREQ_LABEL: &str = "CERTIFICATE REQUEST";
pub const PKCS7_LABEL: &str = "PKCS7";
pub const CMS_LABEL: &str = "CMS";
pub const PRIVKEY_LABEL: &str = "PRIVATE KEY";
pub const ENC_PRIVKEY_LABEL: &str = "ENCRYPTED PRIVATE KEY";
pub const ATTRCERT_LABEL: &str = "ATTRIBUTE CERTIFICATE";
pub const PUBKEY_LABEL: &str = "PUBLIC KEY";

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
