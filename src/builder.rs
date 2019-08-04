use crate::{PemMessage, RawPemHeader};

#[derive(Debug, Default)]
pub struct PemBuilder<'p> {
    label: Option<&'p str>,
    rawheaders: Vec<(&'p str, String)>,
    content: Vec<u8>,
}

impl<'p> PemBuilder<'p> {
    pub fn label(&mut self, label_str: &'p str) -> &mut Self {
        self.label = Some(label_str);
        self
    }

    pub fn header(&mut self, name: &'p str, body: String) -> &mut Self {
        self.rawheaders.push((name, body));
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
        let headers = self
            .rawheaders
            .into_iter()
            .map(|(name, body)| RawPemHeader {
                name: name.to_owned(),
                body,
            })
            .collect();
        PemMessage {
            label,
            rawheaders: headers,
            content: self.content,
        }
    }
}
