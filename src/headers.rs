use crate::parser::pest_err_span;
use pest::error::Error;
use pest::iterators::*;
use pest::Parser;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

/// Struct to store standard PEM header
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PemHeader {
    proc_type: Option<ProcType>,
    content_domain: Option<ContentDomain>,
    dek_info: Option<DEKInfo>,
    /* Not Supported
    originator: Option<Originator>,
    mic_info: Option<MICInfo>,
    recipients: Vec<Recipient>,
    crl: Option<CRL>,
    */
}

impl PemHeader {
    pub(crate) fn from_str(input: &str) -> Result<Self, Error<Rule>> {
        HeaderParser::parse_str(input)
    }
}

impl PemHeader {
    /// Return `true` if the header won't print anything out
    ///
    /// # Note
    /// If the `Proc-Type` header field is not exist,
    /// The header won't display anything
    pub fn is_empty(&self) -> bool {
        self.proc_type.is_none()
    }

    pub(self) fn from_pair(pair: Pair<Rule>) -> Result<Self, Error<Rule>> {
        let mut hdr = PemHeader::default();

        for hdr_entry in pair.into_inner() {
            match hdr_entry.as_rule() {
                Rule::proctype => hdr.proc_type = Some(ProcType::from_pair(hdr_entry)?),
                Rule::contentdomain => {
                    hdr.content_domain = Some(ContentDomain::from_pair(hdr_entry)?)
                }
                Rule::dekinfo => hdr.dek_info = Some(DEKInfo::from_pair(hdr_entry)?),
                Rule::unsupported_hdr => (),
                _ => unreachable!(),
            }
        }
        Ok(hdr)
    }
}

impl Display for PemHeader {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if let Some(proc_type) = &self.proc_type {
            writeln!(f, "{}", proc_type)?;
            if let Some(domain) = &self.content_domain {
                writeln!(f, "{}", domain)?;
            }
            if let Some(dek_info) = &self.dek_info {
                writeln!(f, "{}", dek_info)?;
            }
        }
        Ok(())
    }
}

/// `Proc-Type` header field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcType(pub u32, pub ProcTypeSpecifier);

impl ProcType {
    pub(self) fn from_pair(pair: Pair<Rule>) -> Result<Self, Error<Rule>> {
        let mut pairs = pair.into_inner();

        let procver = pairs.next().unwrap();
        let pemtypes = pairs.next().unwrap();

        let ver = procver
            .as_str()
            .parse::<u32>()
            .map_err(|e| pest_err_span(e.to_string(), &procver))?;
        let types = pemtypes
            .as_str()
            .parse::<ProcTypeSpecifier>()
            .map_err(|_| pest_err_span("Invalid Proc-Type specifier", &pemtypes))?;
        Ok(Self(ver, types))
    }
}

impl Display for ProcType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "Proc-Type: {},{}", self.0, self.1)
    }
}

/// Enumerations for different PEM type
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcTypeSpecifier {
    ENCRYPTED,
    MIC_ONLY,
    MIC_CLEAR,
    CRL,
}

impl FromStr for ProcTypeSpecifier {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ProcTypeSpecifier::*;
        match s {
            "ENCRYPTED" => Ok(ENCRYPTED),
            "MIC-ONLY" => Ok(MIC_ONLY),
            "MIC-CLEAR" => Ok(MIC_CLEAR),
            "CRL" => Ok(CRL),
            _ => Err(()),
        }
    }
}

impl Display for ProcTypeSpecifier {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::ENCRYPTED => write!(f, "ENCRYPTED"),
            Self::MIC_ONLY => write!(f, "MIC-ONLY"),
            Self::MIC_CLEAR => write!(f, "MIC-CLEAR"),
            Self::CRL => write!(f, "CRL"),
        }
    }
}

/// `Content-Domain` header field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDomain(pub String);

impl ContentDomain {
    pub(self) fn from_pair(pair: Pair<Rule>) -> Result<Self, Error<Rule>> {
        let mut pairs = pair.into_inner();
        let descrip = pairs.next().unwrap();
        Ok(Self(descrip.as_str().to_owned()))
    }
}

impl Display for ContentDomain {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "Content-Domain: {}", &self.0)
    }
}

/// `DEK-Info` header field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DEKInfo {
    pub algorithm: String,
    pub parameter: Vec<u8>,
}

impl DEKInfo {
    pub(self) fn from_pair(pair: Pair<Rule>) -> Result<Self, Error<Rule>> {
        let mut pairs = pair.into_inner();

        let dekalgo = pairs.next().unwrap();
        let dekparameters = pairs.next().unwrap();

        let algo = dekalgo.as_str().to_owned();
        let para = hex::decode(dekparameters.as_str())
            .map_err(|e| pest_err_span(e.to_string(), &dekparameters))?;
        Ok(DEKInfo {
            algorithm: algo,
            parameter: para,
        })
    }
}

impl Display for DEKInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if self.parameter.is_empty() {
            write!(f, "DEK-Info: {}", &self.algorithm)
        } else {
            write!(
                f,
                "DEK-Info: {},{}",
                &self.algorithm,
                hex::encode_upper(&self.parameter)
            )
        }
    }
}

#[derive(Parser)]
#[grammar = "headers.pest"]
struct HeaderParser;

impl HeaderParser {
    pub fn parse_str(input: &str) -> Result<PemHeader, Error<Rule>> {
        let pemhdr = HeaderParser::parse(Rule::pemhdr, input)?.next().unwrap();
        Ok(PemHeader::from_pair(pemhdr)?)
    }
}

/// Some unimplemented things
#[allow(dead_code)]
#[cfg(feature = "unstable")]
mod unstable {
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
}
