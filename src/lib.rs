extern crate pest;
#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate lazy_static;

mod builder;
mod parser;

#[derive(Debug)]
pub struct PemMessage {
    label: String,
    rawheaders: Vec<RawPemHeader>,
    content: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct RawPemHeader {
    name: String,
    body: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
