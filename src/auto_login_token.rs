use encryption::aes::AesKey;

#[derive(::prost::Message)]
pub struct AutoLoginToken {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(int64, tag = "2")]
    pub expires: i64,
}

impl AutoLoginToken {
    pub fn new(client_id: String, expires: i64) -> Self {
        Self { client_id, expires }
    }

    pub fn to_string(&self, key: AesKey) -> String {
        let mut result = Vec::new();

        prost::Message::encode(self, &mut result).unwrap();
        let result = key.encrypt(result.as_slice());
        hex::encode(result)
    }

    pub fn parse(token: &str, key: AesKey) -> Self {
        let encrypted = hex::decode(token).unwrap();
        let bytes = key.encrypt(encrypted.as_slice());
        prost::Message::decode(bytes.as_slice()).unwrap()
    }
}
