use crate::RawPemHeader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemHeader {
    proc_type: Option<ProcType>,
    content_domain: Option<String>,
    dek_info: Option<DEKInfo>,
    originator: Option<Originator>,
    mic_info: Option<MICInfo>,
    recipients: Vec<Recipient>,
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
