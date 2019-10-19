use crate::headers::Rule as HeadersRule;
use crate::parser::Rule as PemRule;
use failure::Fail;
use pest::error::Error as PestError;
use std::fmt;

pub type PemResult<T> = Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    PemParserError(PestError<PemRule>),
    HeaderParserError(PestError<HeadersRule>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::PemParserError(err) => err.fmt(f),
            Error::HeaderParserError(err) => err.fmt(f),
        }
    }
}

impl Fail for Error {}

impl From<PestError<PemRule>> for Error {
    fn from(err: PestError<PemRule>) -> Self {
        Error::PemParserError(err)
    }
}

impl From<PestError<HeadersRule>> for Error {
    fn from(err: PestError<HeadersRule>) -> Self {
        Error::HeaderParserError(err)
    }
}
