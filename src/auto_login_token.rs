use encryption::aes::AesKey;
use rust_extensions::date_time::DateTimeAsMicroseconds;

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

    pub fn to_string(&self, key: &AesKey) -> String {
        let mut result = Vec::new();

        prost::Message::encode(self, &mut result).unwrap();
        let result = key.encrypt(result.as_slice());
        hex::encode(result)
    }

    pub fn parse(token: &str, key: &AesKey) -> Option<Self> {
        let encrypted = hex::decode(token);
        if encrypted.is_err() {
            return None;
        }

        let bytes = key.encrypt(encrypted.unwrap().as_slice());

        let result: Result<Self, _> = prost::Message::decode(bytes.as_slice());

        if result.is_err() {
            return None;
        }

        Some(result.unwrap())
    }

    pub fn is_expired(&self, now: DateTimeAsMicroseconds) -> bool {
        let expires = DateTimeAsMicroseconds::new(self.expires);
        expires.unix_microseconds < now.unix_microseconds
    }
}
