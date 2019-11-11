extern crate easypem;
use easypem::{headers::*, PemMessage};

#[test]
fn simple_serialize() {
    use easypem::{headers::PemHeader, PemMessage};

    let pem = PemMessage {
        label: "MESSAGE".to_owned(),
        headers: PemHeader::default(),
        content: b"This is a message".to_vec(),
    };

    assert_eq!(
        &pem.to_string(),
        "-----BEGIN MESSAGE-----
VGhpcyBpcyBhIG1lc3NhZ2U=
-----END MESSAGE-----"
    );
}
