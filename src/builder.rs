use crate::headers::PemHeader;
use crate::PemMessage;

#[derive(Debug, Default)]
pub struct PemBuilder<'p> {
    label: Option<&'p str>,
    headers: Option<PemHeader>,
    content: Vec<u8>,
}

impl<'p> PemBuilder<'p> {
    pub fn label(&mut self, label_str: &'p str) -> &mut Self {
        self.label = Some(label_str);
        self
    }

    pub fn headers(&mut self, headers: PemHeader) -> &mut Self {
        self.headers = Some(headers);
        self
    }

    pub fn content(&mut self, data: Vec<u8>) -> &mut Self {
        self.content = data;
        self
    }

    pub fn build(self) -> PemMessage {
        let label = if let Some(s) = self.label {
            s.to_owned()
        } else {
            String::new()
        };
        let headers = self.headers.unwrap_or_default();
        PemMessage {
            label,
            headers,
            content: self.content,
        }
    }
}
