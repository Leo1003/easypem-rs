use crate::parser::{custom_error_span, Rule};
use crate::RawPemHeader;
use pest::error::{Error, ErrorVariant};
use pest::iterators::{Pair, Pairs};
use std::borrow::Cow;
use std::str::FromStr;

/// Struct to store standard PEM header
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PemHeader {
    proc_type: Option<ProcType>,
    content_domain: Option<String>,
    dek_info: Option<DEKInfo>,
    originator: Option<Originator>,
    mic_info: Option<MICInfo>,
    recipients: Vec<Recipient>,
    crl: Option<CRL>,
}

impl PemHeader {
    pub(crate) fn from_pairs(mut pairs: Pairs<'_, Rule>) -> Result<Self, Error<Rule>> {
        if let Some(entry) = pairs.next() {
            let mut newheader = PemHeader::default();
            // The first entry should be Proc-Type
            newheader.parse_proc_type(entry)?;

            Ok(newheader)
        } else {
            // No header exists
            // Return an empty headers
            Ok(PemHeader::default())
        }
    }

    fn parse_proc_type(&mut self, entry: Pair<'_, Rule>) -> Result<(), Error<Rule>> {
        let (name, body) = pair_to_raw(entry.clone());
        if name == "Proc-Type" {
            let mut iter = body.splitn(2, ",");
            if let Some((n, s)) = iter.next().iter().zip(iter.next()).next() {
                let num = n
                    .parse::<u32>()
                    .map_err(|e| custom_error_span(&e.to_string(), &entry))?;
                let spec = match s {
                    "ENCRYPTED" => ProcTypeSpecifier::ENCRYPTED,
                    "MIC-ONLY" => ProcTypeSpecifier::MIC_ONLY,
                    "MIC-CLEAR" => ProcTypeSpecifier::MIC_CLEAR,
                    "CRL" => ProcTypeSpecifier::CRL,
                    _ => return Err(custom_error_span("Invalid Proc-Type specifier", &entry)),
                };

                self.proc_type = Some(ProcType(num, spec));
            } else {
                return Err(custom_error_span("Invalid Proc-Type content", &entry));
            }
            Ok(())
        } else {
            Err(custom_error_span("Expected Proc-Type entry", &entry))
        }
    }

    fn parse_content_domain(&mut self, entry: Pair<'_, Rule>) -> Result<(), Error<Rule>> {
        let (name, body) = pair_to_raw(entry.clone());
        if name == "Content-Domain" {
            self.content_domain = Some(body.into_owned());
            Ok(())
        } else {
            Err(custom_error_span("Expected Content-Domain entry", &entry))
        }
    }
}

/// `Proc-Type` header field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcType(pub u32, pub ProcTypeSpecifier);

/// Enumerations for different PEM type
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcTypeSpecifier {
    ENCRYPTED,
    MIC_ONLY,
    MIC_CLEAR,
    CRL,
}

/// `DEK-Info` header field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DEKInfo {
    pub algorithm: String,
    pub parameter: Vec<u8>,
}

/// Certificate stored in base64 form
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate(Vec<u8>);

/// Certificate Revoked List stored in base64 form
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CRL(Vec<u8>);

/// Represent single recipient related fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Asymmetric {
        /// `Recipient-ID-Asymmetric` field
        originator_id: AsymmetricID,
        /// The following `Key-Info` field
        key_info: KeyInfoAsymmetric,
    },
    Symmetric {
        /// `Recipient-ID-Symmetric` field
        originator_id: SymmetricID,
        /// The following `Key-Info` field
        key_info: KeyInfoSymmetric,
    },
}

/// Represent originator related fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Originator {
    Asymmetric {
        /// Asymmetric originator case
        originator_id: AsymmetricOriginator,
        /// The following `Key-Info` field (if present)
        key_info: Option<KeyInfoAsymmetric>,
        /// Zero or more `Issuer-Certificate` fields
        issuer_certificate: Vec<Certificate>,
        /// `MIC-Info` field
        mic_info: MICInfo,
    },
    Symmetric {
        /// `Originator-ID-Symmetric` field
        originator_id: SymmetricID,
        /// The following `Key-Info` field (if present)
        key_info: Option<KeyInfoSymmetric>,
    },
}

/// Represent originator using asymmetric in either ID or certificate form
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsymmetricOriginator {
    /// `Originator-ID-Asymmetric` field
    ID(AsymmetricID),
    /// `Originator-Certificate` field
    Cert(Certificate),
}

/// `Key-Info` field for asymmetric case
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfoAsymmetric {
    /// Asymmetric algorithm
    pub algorithm: String,
    /// Base64 DEK data
    pub dek: Vec<u8>,
}

/// `Key-Info` field for symmetric case
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfoSymmetric {
    /// Symmetric algorithm
    pub algorithm: String,
    /// Integrity check algorithm
    pub mic_algorithm: String,
    /// Hexadecimal DEK data
    pub dek: Vec<u8>,
    /// Hexadecimal MIC data
    pub mic: Vec<u8>,
}

/// Personal ID for asymmetric case
///
/// `Originator-ID-Asymmetric` field for originator
///
/// `Recipient-ID-Asymmetric` field for recipient
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsymmetricID(pub String, pub String);

/// Personal ID for symmetric case
///
/// `Originator-ID-Symmetric` field for originator
///
/// `Recipient-ID-Symmetric` field for recipient
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricID(pub String, pub String, pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MICInfo {
    /// Message integrity check algorithm
    pub algorithm: String,
    /// IK algorithm
    pub ik_algorithm: String,
    /// Base64 signature data
    pub signature: Vec<u8>,
}

fn pair_to_raw<'i>(entry: Pair<'i, Rule>) -> (&'i str, Cow<'i, str>) {
    let mut entry_inner = entry.into_inner();
    let name = entry_inner.next().unwrap().as_str();
    let mut body = Cow::Borrowed("");
    // Unfold the header body
    for (n, line) in entry_inner.next().unwrap().as_str().lines().enumerate() {
        if n == 0 {
            body = Cow::Borrowed(line);
        } else {
            body.to_mut().push_str(line.trim());
        }
    }
    (name, body)
}

fn peek_entry_name<'i>(entry: &Pair<'i, Rule>) -> &'i str {
    let mut entry_inner = entry.clone().into_inner();
    entry_inner.next().unwrap().as_str()
}
