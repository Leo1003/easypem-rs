extern crate pest;
#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate lazy_static;

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
